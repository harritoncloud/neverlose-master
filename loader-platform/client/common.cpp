#include "common.hpp"

#include <ShlObj.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cstring>
#include <limits>
#include <sstream>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")

namespace nl
{
    namespace
    {
        std::string ascii_lower(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char character)
            {
                return static_cast<char>(std::tolower(character));
            });
            return value;
        }

        void append_utf8(std::string& output, const std::uint32_t codepoint)
        {
            if (codepoint <= 0x7f)
            {
                output.push_back(static_cast<char>(codepoint));
            }
            else if (codepoint <= 0x7ff)
            {
                output.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
                output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
            }
            else if (codepoint <= 0xffff)
            {
                output.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
                output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
                output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
            }
            else if (codepoint <= 0x10ffff)
            {
                output.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
                output.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
                output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
                output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
            }
            else
            {
                throw std::runtime_error("JSON contains an invalid Unicode codepoint");
            }
        }

        class json_reader
        {
        public:
            explicit json_reader(const std::string_view document) : document_(document) {}

            std::string find_string(const std::string_view expected_key)
            {
                return find(expected_key, true).text;
            }

            std::int64_t find_integer(const std::string_view expected_key)
            {
                return find(expected_key, false).number;
            }

        private:
            struct result
            {
                std::string text;
                std::int64_t number = 0;
            };

            result find(const std::string_view expected_key, const bool want_string)
            {
                skip_space();
                expect('{');
                skip_space();
                if (consume('}'))
                    throw std::runtime_error("JSON field is missing: " + std::string(expected_key));

                for (;;)
                {
                    const std::string key = parse_string();
                    skip_space();
                    expect(':');
                    skip_space();
                    if (key == expected_key)
                    {
                        result value;
                        if (want_string)
                            value.text = parse_string();
                        else
                            value.number = parse_integer();
                        return value;
                    }
                    skip_value(0);
                    skip_space();
                    if (consume('}'))
                        break;
                    expect(',');
                    skip_space();
                }
                throw std::runtime_error("JSON field is missing: " + std::string(expected_key));
            }

            std::string parse_string()
            {
                expect('"');
                std::string output;
                while (position_ < document_.size())
                {
                    const unsigned char character = static_cast<unsigned char>(document_[position_++]);
                    if (character == '"')
                        return output;
                    if (character < 0x20)
                        throw std::runtime_error("JSON string contains a control character");
                    if (character != '\\')
                    {
                        output.push_back(static_cast<char>(character));
                        continue;
                    }
                    if (position_ >= document_.size())
                        throw std::runtime_error("JSON escape is incomplete");
                    switch (document_[position_++])
                    {
                    case '"': output.push_back('"'); break;
                    case '\\': output.push_back('\\'); break;
                    case '/': output.push_back('/'); break;
                    case 'b': output.push_back('\b'); break;
                    case 'f': output.push_back('\f'); break;
                    case 'n': output.push_back('\n'); break;
                    case 'r': output.push_back('\r'); break;
                    case 't': output.push_back('\t'); break;
                    case 'u':
                    {
                        std::uint32_t codepoint = parse_hex4();
                        if (codepoint >= 0xd800 && codepoint <= 0xdbff)
                        {
                            if (position_ + 2 > document_.size() || document_[position_] != '\\' || document_[position_ + 1] != 'u')
                                throw std::runtime_error("JSON high surrogate has no pair");
                            position_ += 2;
                            const std::uint32_t low = parse_hex4();
                            if (low < 0xdc00 || low > 0xdfff)
                                throw std::runtime_error("JSON surrogate pair is invalid");
                            codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (low - 0xdc00);
                        }
                        else if (codepoint >= 0xdc00 && codepoint <= 0xdfff)
                        {
                            throw std::runtime_error("JSON low surrogate has no pair");
                        }
                        append_utf8(output, codepoint);
                        break;
                    }
                    default:
                        throw std::runtime_error("JSON escape is invalid");
                    }
                }
                throw std::runtime_error("JSON string is unterminated");
            }

            std::uint32_t parse_hex4()
            {
                if (position_ + 4 > document_.size())
                    throw std::runtime_error("JSON Unicode escape is incomplete");
                std::uint32_t value = 0;
                for (int index = 0; index < 4; ++index)
                {
                    const char character = document_[position_++];
                    value <<= 4;
                    if (character >= '0' && character <= '9')
                        value |= static_cast<std::uint32_t>(character - '0');
                    else if (character >= 'a' && character <= 'f')
                        value |= static_cast<std::uint32_t>(character - 'a' + 10);
                    else if (character >= 'A' && character <= 'F')
                        value |= static_cast<std::uint32_t>(character - 'A' + 10);
                    else
                        throw std::runtime_error("JSON Unicode escape is invalid");
                }
                return value;
            }

            std::int64_t parse_integer()
            {
                const std::size_t start = position_;
                if (consume('-') && position_ >= document_.size())
                    throw std::runtime_error("JSON number is incomplete");
                if (consume('0'))
                {
                    if (position_ < document_.size() && std::isdigit(static_cast<unsigned char>(document_[position_])))
                        throw std::runtime_error("JSON number has a leading zero");
                }
                else
                {
                    if (position_ >= document_.size() || document_[position_] < '1' || document_[position_] > '9')
                        throw std::runtime_error("JSON integer is invalid");
                    while (position_ < document_.size() && std::isdigit(static_cast<unsigned char>(document_[position_])))
                        ++position_;
                }
                const std::string_view token = document_.substr(start, position_ - start);
                std::int64_t value = 0;
                const auto parsed = std::from_chars(token.data(), token.data() + token.size(), value);
                if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size())
                    throw std::runtime_error("JSON integer is out of range");
                return value;
            }

            void skip_value(const unsigned depth)
            {
                if (depth > 16)
                    throw std::runtime_error("JSON nesting is too deep");
                skip_space();
                if (position_ >= document_.size())
                    throw std::runtime_error("JSON value is missing");
                switch (document_[position_])
                {
                case '"':
                    static_cast<void>(parse_string());
                    return;
                case '{':
                    ++position_;
                    skip_space();
                    if (consume('}'))
                        return;
                    for (;;)
                    {
                        static_cast<void>(parse_string());
                        skip_space();
                        expect(':');
                        skip_value(depth + 1);
                        skip_space();
                        if (consume('}'))
                            return;
                        expect(',');
                        skip_space();
                    }
                case '[':
                    ++position_;
                    skip_space();
                    if (consume(']'))
                        return;
                    for (;;)
                    {
                        skip_value(depth + 1);
                        skip_space();
                        if (consume(']'))
                            return;
                        expect(',');
                        skip_space();
                    }
                case 't': consume_literal("true"); return;
                case 'f': consume_literal("false"); return;
                case 'n': consume_literal("null"); return;
                default:
                    skip_number();
                    return;
                }
            }

            void skip_number()
            {
                const std::size_t start = position_;
                if (position_ < document_.size() && document_[position_] == '-')
                    ++position_;
                while (position_ < document_.size())
                {
                    const char character = document_[position_];
                    if ((character >= '0' && character <= '9') || character == '.' || character == 'e' || character == 'E' || character == '+' || character == '-')
                        ++position_;
                    else
                        break;
                }
                if (position_ == start)
                    throw std::runtime_error("JSON value is invalid");
            }

            void consume_literal(const std::string_view literal)
            {
                if (document_.substr(position_, literal.size()) != literal)
                    throw std::runtime_error("JSON literal is invalid");
                position_ += literal.size();
            }

            void skip_space()
            {
                while (position_ < document_.size())
                {
                    const char character = document_[position_];
                    if (character != ' ' && character != '\t' && character != '\r' && character != '\n')
                        break;
                    ++position_;
                }
            }

            void expect(const char expected)
            {
                if (!consume(expected))
                    throw std::runtime_error(std::string("JSON expected '") + expected + "'");
            }

            bool consume(const char expected)
            {
                if (position_ >= document_.size() || document_[position_] != expected)
                    return false;
                ++position_;
                return true;
            }

            std::string_view document_;
            std::size_t position_ = 0;
        };
    }

    win_handle& win_handle::operator=(win_handle&& other) noexcept
    {
        if (this != &other)
            reset(other.release());
        return *this;
    }

    win_handle::~win_handle()
    {
        reset();
    }

    win_handle::operator bool() const noexcept
    {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }

    HANDLE win_handle::release() noexcept
    {
        const HANDLE value = value_;
        value_ = INVALID_HANDLE_VALUE;
        return value;
    }

    void win_handle::reset(const HANDLE value) noexcept
    {
        if (*this)
            CloseHandle(value_);
        value_ = value;
    }

    [[noreturn]] void throw_last_error(const std::string_view operation, const DWORD error)
    {
        char* message = nullptr;
        const DWORD length = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<char*>(&message),
            0,
            nullptr);
        std::string detail = length && message ? trim_ascii(std::string(message, length)) : "Windows error " + std::to_string(error);
        if (message)
            LocalFree(message);
        throw std::runtime_error(std::string(operation) + ": " + detail);
    }

    [[noreturn]] void throw_ntstatus(const std::string_view operation, const NTSTATUS status)
    {
        std::ostringstream stream;
        stream << operation << ": NTSTATUS 0x" << std::hex << static_cast<unsigned long>(status);
        throw std::runtime_error(stream.str());
    }

    std::wstring utf8_to_wide(const std::string_view value)
    {
        if (value.empty())
            return {};
        const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
        if (length <= 0)
            throw_last_error("MultiByteToWideChar");
        std::wstring output(static_cast<std::size_t>(length), L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), output.data(), length) != length)
            throw_last_error("MultiByteToWideChar");
        return output;
    }

    std::string wide_to_utf8(const std::wstring_view value)
    {
        if (value.empty())
            return {};
        const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (length <= 0)
            throw_last_error("WideCharToMultiByte");
        std::string output(static_cast<std::size_t>(length), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), output.data(), length, nullptr, nullptr) != length)
            throw_last_error("WideCharToMultiByte");
        return output;
    }

    std::string trim_ascii(std::string value)
    {
        const auto is_space = [](const unsigned char character) { return std::isspace(character) != 0; };
        value.erase(value.begin(), std::find_if(value.begin(), value.end(), [&](const char character) { return !is_space(static_cast<unsigned char>(character)); }));
        value.erase(std::find_if(value.rbegin(), value.rend(), [&](const char character) { return !is_space(static_cast<unsigned char>(character)); }).base(), value.end());
        return value;
    }

    bytes read_file(const std::filesystem::path& path, const std::size_t maximum_bytes)
    {
        win_handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!file)
            throw_last_error("CreateFileW(read)");
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file.get(), &size))
            throw_last_error("GetFileSizeEx");
        if (size.QuadPart < 0 || static_cast<unsigned long long>(size.QuadPart) > maximum_bytes)
            throw std::runtime_error("File size is outside the allowed range");
        bytes output(static_cast<std::size_t>(size.QuadPart));
        std::size_t offset = 0;
        while (offset < output.size())
        {
            const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(output.size() - offset, 1u << 20));
            DWORD read = 0;
            if (!ReadFile(file.get(), output.data() + offset, chunk, &read, nullptr))
                throw_last_error("ReadFile");
            if (read == 0)
                throw std::runtime_error("Unexpected end of file");
            offset += read;
        }
        return output;
    }

    void write_file_atomic(const std::filesystem::path& path, const std::span<const std::uint8_t> content)
    {
        std::filesystem::create_directories(path.parent_path());
        const std::filesystem::path temporary = path.wstring() + L".tmp-" + utf8_to_wide(hex_encode(random_bytes(8)));
        try
        {
            win_handle file(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, nullptr));
            if (!file)
                throw_last_error("CreateFileW(write)");
            std::size_t offset = 0;
            while (offset < content.size())
            {
                const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(content.size() - offset, 1u << 20));
                DWORD written = 0;
                if (!WriteFile(file.get(), content.data() + offset, chunk, &written, nullptr) || written != chunk)
                    throw_last_error("WriteFile");
                offset += written;
            }
            if (!FlushFileBuffers(file.get()))
                throw_last_error("FlushFileBuffers");
            file.reset();
            if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw_last_error("MoveFileExW");
        }
        catch (...)
        {
            DeleteFileW(temporary.c_str());
            throw;
        }
    }

    std::filesystem::path executable_path()
    {
        std::wstring path(32768, L'\0');
        const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0 || length >= path.size())
            throw_last_error("GetModuleFileNameW");
        path.resize(length);
        return path;
    }

    std::filesystem::path local_app_data_path()
    {
        PWSTR path = nullptr;
        const HRESULT result = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &path);
        if (FAILED(result) || !path)
            throw std::runtime_error("SHGetKnownFolderPath failed");
        std::filesystem::path output(path);
        CoTaskMemFree(path);
        return output;
    }

    std::string base64_encode(const std::span<const std::uint8_t> value)
    {
        DWORD length = 0;
        if (!CryptBinaryToStringA(value.data(), static_cast<DWORD>(value.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &length))
            throw_last_error("CryptBinaryToStringA");
        std::string output(length, '\0');
        if (!CryptBinaryToStringA(value.data(), static_cast<DWORD>(value.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, output.data(), &length))
            throw_last_error("CryptBinaryToStringA");
        output.resize(std::strlen(output.c_str()));
        while (!output.empty() && output.back() == '=')
            output.pop_back();
        return output;
    }

    bytes base64_decode(const std::string_view input, const std::size_t minimum, const std::size_t maximum)
    {
        std::string normalized = trim_ascii(std::string(input));
        for (char& character : normalized)
        {
            if (character == '-')
                character = '+';
            else if (character == '_')
                character = '/';
            else if (!((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
                (character >= '0' && character <= '9') || character == '+' || character == '/' || character == '='))
                throw std::runtime_error("Base64 value contains unsupported characters");
        }
        if (const auto padding = normalized.find('='); padding != std::string::npos && normalized.find_first_not_of('=', padding) != std::string::npos)
            throw std::runtime_error("Base64 padding is invalid");
        while (normalized.size() % 4 != 0)
            normalized.push_back('=');
        DWORD length = 0;
        if (!CryptStringToBinaryA(normalized.c_str(), static_cast<DWORD>(normalized.size()), CRYPT_STRING_BASE64, nullptr, &length, nullptr, nullptr))
            throw_last_error("CryptStringToBinaryA");
        if (length < minimum || length > maximum)
            throw std::runtime_error("Decoded Base64 size is outside the allowed range");
        bytes output(length);
        if (!CryptStringToBinaryA(normalized.c_str(), static_cast<DWORD>(normalized.size()), CRYPT_STRING_BASE64, output.data(), &length, nullptr, nullptr))
            throw_last_error("CryptStringToBinaryA");
        output.resize(length);
        return output;
    }

    std::string hex_encode(const std::span<const std::uint8_t> value)
    {
        constexpr char alphabet[] = "0123456789abcdef";
        std::string output(value.size() * 2, '\0');
        for (std::size_t index = 0; index < value.size(); ++index)
        {
            output[index * 2] = alphabet[value[index] >> 4];
            output[index * 2 + 1] = alphabet[value[index] & 0x0f];
        }
        return output;
    }

    bytes hex_decode(const std::string_view value, const std::size_t expected_size)
    {
        if (value.size() != expected_size * 2)
            throw std::runtime_error("Hex value has an invalid size");
        bytes output(expected_size);
        const auto digit = [](const char character) -> std::uint8_t
        {
            if (character >= '0' && character <= '9') return static_cast<std::uint8_t>(character - '0');
            if (character >= 'a' && character <= 'f') return static_cast<std::uint8_t>(character - 'a' + 10);
            if (character >= 'A' && character <= 'F') return static_cast<std::uint8_t>(character - 'A' + 10);
            throw std::runtime_error("Hex value contains an invalid character");
        };
        for (std::size_t index = 0; index < expected_size; ++index)
            output[index] = static_cast<std::uint8_t>((digit(value[index * 2]) << 4) | digit(value[index * 2 + 1]));
        return output;
    }

    std::string json_escape(const std::string_view value)
    {
        std::string output;
        output.reserve(value.size() + 8);
        for (const unsigned char character : value)
        {
            switch (character)
            {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (character < 0x20)
                {
                    constexpr char alphabet[] = "0123456789abcdef";
                    output += "\\u00";
                    output.push_back(alphabet[character >> 4]);
                    output.push_back(alphabet[character & 0x0f]);
                }
                else
                {
                    output.push_back(static_cast<char>(character));
                }
            }
        }
        return output;
    }

    std::string json_string(const std::string_view document, const std::string_view key)
    {
        return json_reader(document).find_string(key);
    }

    std::int64_t json_integer(const std::string_view document, const std::string_view key)
    {
        return json_reader(document).find_integer(key);
    }

    std::string http_response::text() const
    {
        return {reinterpret_cast<const char*>(body.data()), body.size()};
    }

    std::string http_response::header(const std::string_view name) const
    {
        const auto iterator = headers.find(ascii_lower(std::string(name)));
        if (iterator == headers.end())
            throw std::runtime_error("HTTP response header is missing: " + std::string(name));
        return iterator->second;
    }
}
