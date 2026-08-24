#include "common.hpp"

#include <winhttp.h>

#include <algorithm>
#include <array>
#include <cwchar>
#include <limits>

#pragma comment(lib, "winhttp.lib")

namespace nl
{
    namespace
    {
        class internet_handle
        {
        public:
            internet_handle() = default;
            explicit internet_handle(HINTERNET value) : value_(value) {}
            internet_handle(const internet_handle&) = delete;
            internet_handle& operator=(const internet_handle&) = delete;
            internet_handle(internet_handle&& other) noexcept : value_(other.release()) {}
            internet_handle& operator=(internet_handle&& other) noexcept
            {
                if (this != &other)
                    reset(other.release());
                return *this;
            }
            ~internet_handle() { reset(); }
            [[nodiscard]] HINTERNET get() const noexcept { return value_; }
            [[nodiscard]] explicit operator bool() const noexcept { return value_ != nullptr; }
            [[nodiscard]] HINTERNET release() noexcept
            {
                const auto value = value_;
                value_ = nullptr;
                return value;
            }
            void reset(HINTERNET value = nullptr) noexcept
            {
                if (value_)
                    WinHttpCloseHandle(value_);
                value_ = value;
            }

        private:
            HINTERNET value_ = nullptr;
        };

        std::string ascii_lower(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char character)
            {
                return static_cast<char>(std::tolower(character));
            });
            return value;
        }

        std::wstring query_header(HINTERNET request, const std::wstring& name)
        {
            DWORD length = 0;
            WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, name.c_str(), nullptr, &length, WINHTTP_NO_HEADER_INDEX);
            const DWORD query_error = GetLastError();
            if (query_error == ERROR_WINHTTP_HEADER_NOT_FOUND)
                return {};
            if (query_error != ERROR_INSUFFICIENT_BUFFER || length < sizeof(wchar_t))
                throw_last_error("WinHttpQueryHeaders(size)", query_error);
            std::wstring value(length / sizeof(wchar_t), L'\0');
            if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, name.c_str(), value.data(), &length, WINHTTP_NO_HEADER_INDEX))
                throw_last_error("WinHttpQueryHeaders");
            value.resize(length / sizeof(wchar_t));
            while (!value.empty() && value.back() == L'\0')
                value.pop_back();
            return value;
        }

        void validate_path(const std::string_view path)
        {
            if (path.empty() || path.front() != '/' || path.find("://") != std::string_view::npos ||
                path.find('\r') != std::string_view::npos || path.find('\n') != std::string_view::npos)
                throw std::runtime_error("HTTP path is invalid");
        }
    }

    struct http_client::implementation
    {
        internet_handle session;
        internet_handle connection;
        std::wstring base_path;
        INTERNET_PORT port = 0;

        http_response request(
            const wchar_t* method,
            const std::string_view path,
            const std::string_view body,
            const std::string_view bearer_token,
            const std::size_t maximum_response_bytes,
            const std::span<const std::string_view> response_headers) const
        {
            validate_path(path);
            if (maximum_response_bytes == 0 || maximum_response_bytes > 256ull * 1024 * 1024 + 64)
                throw std::runtime_error("HTTP response limit is invalid");
            if (body.size() > std::numeric_limits<DWORD>::max())
                throw std::runtime_error("HTTP request body is too large");
            if (bearer_token.find('\r') != std::string_view::npos || bearer_token.find('\n') != std::string_view::npos)
                throw std::runtime_error("Bearer token is invalid");

            const std::wstring object = base_path + utf8_to_wide(path);
            LPCWSTR accepted[] = {L"application/json", L"application/octet-stream", nullptr};
            internet_handle request(WinHttpOpenRequest(
                connection.get(),
                method,
                object.c_str(),
                nullptr,
                WINHTTP_NO_REFERER,
                accepted,
                WINHTTP_FLAG_SECURE));
            if (!request)
                throw_last_error("WinHttpOpenRequest");

            DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy)))
                throw_last_error("WinHttpSetOption(redirect)");

            std::wstring headers = L"Accept: application/json, application/octet-stream\r\n";
            if (!body.empty())
                headers += L"Content-Type: application/json; charset=utf-8\r\n";
            if (!bearer_token.empty())
                headers += L"Authorization: Bearer " + utf8_to_wide(bearer_token) + L"\r\n";

            if (!WinHttpSendRequest(
                request.get(),
                headers.c_str(),
                static_cast<DWORD>(headers.size()),
                body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
                static_cast<DWORD>(body.size()),
                static_cast<DWORD>(body.size()),
                0))
                throw_last_error("WinHttpSendRequest");
            if (!WinHttpReceiveResponse(request.get(), nullptr))
                throw_last_error("WinHttpReceiveResponse");

            http_response response;
            DWORD status_size = sizeof(response.status);
            if (!WinHttpQueryHeaders(
                request.get(),
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &response.status,
                &status_size,
                WINHTTP_NO_HEADER_INDEX))
                throw_last_error("WinHttpQueryHeaders(status)");

            for (const std::string_view header_name : response_headers)
            {
                const std::wstring value = query_header(request.get(), utf8_to_wide(header_name));
                if (!value.empty())
                    response.headers.emplace(ascii_lower(std::string(header_name)), wide_to_utf8(value));
            }

            if (const std::wstring content_length = query_header(request.get(), L"Content-Length"); !content_length.empty())
            {
                wchar_t* end = nullptr;
                const unsigned long long parsed = std::wcstoull(content_length.c_str(), &end, 10);
                if (!end || *end != L'\0' || parsed > maximum_response_bytes)
                    throw std::runtime_error("HTTP response exceeds the allowed size");
                response.body.reserve(static_cast<std::size_t>(parsed));
            }

            for (;;)
            {
                DWORD available = 0;
                if (!WinHttpQueryDataAvailable(request.get(), &available))
                    throw_last_error("WinHttpQueryDataAvailable");
                if (available == 0)
                    break;
                if (response.body.size() + available > maximum_response_bytes)
                    throw std::runtime_error("HTTP response exceeds the allowed size");
                const std::size_t offset = response.body.size();
                response.body.resize(offset + available);
                DWORD received = 0;
                if (!WinHttpReadData(request.get(), response.body.data() + offset, available, &received))
                    throw_last_error("WinHttpReadData");
                if (received == 0)
                    throw std::runtime_error("HTTP response ended unexpectedly");
                response.body.resize(offset + received);
            }
            return response;
        }
    };

    http_client::http_client(std::string base_url) : implementation_(std::make_unique<implementation>())
    {
        while (base_url.size() > 8 && base_url.back() == '/')
            base_url.pop_back();
        const std::wstring wide_url = utf8_to_wide(base_url);
        URL_COMPONENTS components{};
        components.dwStructSize = sizeof(components);
        components.dwHostNameLength = static_cast<DWORD>(-1);
        components.dwUrlPathLength = static_cast<DWORD>(-1);
        components.dwExtraInfoLength = static_cast<DWORD>(-1);
        components.dwUserNameLength = static_cast<DWORD>(-1);
        components.dwPasswordLength = static_cast<DWORD>(-1);
        if (!WinHttpCrackUrl(wide_url.c_str(), static_cast<DWORD>(wide_url.size()), 0, &components))
            throw_last_error("WinHttpCrackUrl");
        if (components.nScheme != INTERNET_SCHEME_HTTPS || components.dwHostNameLength == 0 ||
            components.dwUserNameLength != 0 || components.dwPasswordLength != 0 || components.dwExtraInfoLength != 0)
            throw std::runtime_error("Loader server URL must be a plain HTTPS origin");

        const std::wstring host(components.lpszHostName, components.dwHostNameLength);
        implementation_->port = components.nPort;
        if (components.dwUrlPathLength > 0)
        {
            implementation_->base_path.assign(components.lpszUrlPath, components.dwUrlPathLength);
            while (implementation_->base_path.size() > 1 && implementation_->base_path.back() == L'/')
                implementation_->base_path.pop_back();
            if (implementation_->base_path == L"/")
                implementation_->base_path.clear();
        }

        implementation_->session = internet_handle(WinHttpOpen(
            L"NL Loader/1.0",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0));
        if (!implementation_->session)
            throw_last_error("WinHttpOpen");
        DWORD secure_protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
        secure_protocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
        if (!WinHttpSetOption(
                implementation_->session.get(),
                WINHTTP_OPTION_SECURE_PROTOCOLS,
                &secure_protocols,
                sizeof(secure_protocols)))
            throw_last_error("WinHttpSetOption(secure protocols)");
        if (!WinHttpSetTimeouts(implementation_->session.get(), 10'000, 15'000, 15'000, 90'000))
            throw_last_error("WinHttpSetTimeouts");
        implementation_->connection = internet_handle(WinHttpConnect(implementation_->session.get(), host.c_str(), implementation_->port, 0));
        if (!implementation_->connection)
            throw_last_error("WinHttpConnect");
    }

    http_client::http_client(http_client&&) noexcept = default;
    http_client& http_client::operator=(http_client&&) noexcept = default;
    http_client::~http_client() = default;

    http_response http_client::get(const std::string_view path, const std::size_t maximum_response_bytes) const
    {
        return implementation_->request(L"GET", path, {}, {}, maximum_response_bytes, {});
    }

    http_response http_client::post_json(
        const std::string_view path,
        const std::string_view body,
        const std::string_view bearer_token,
        const std::size_t maximum_response_bytes,
        const std::span<const std::string_view> response_headers) const
    {
        return implementation_->request(L"POST", path, body, bearer_token, maximum_response_bytes, response_headers);
    }
}
