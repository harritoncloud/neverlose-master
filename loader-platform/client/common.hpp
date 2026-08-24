#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace nl
{
    using bytes = std::vector<std::uint8_t>;

    class win_handle
    {
    public:
        win_handle() noexcept = default;
        explicit win_handle(HANDLE value) noexcept : value_(value) {}
        win_handle(const win_handle&) = delete;
        win_handle& operator=(const win_handle&) = delete;
        win_handle(win_handle&& other) noexcept : value_(other.release()) {}
        win_handle& operator=(win_handle&& other) noexcept;
        ~win_handle();

        [[nodiscard]] HANDLE get() const noexcept { return value_; }
        [[nodiscard]] explicit operator bool() const noexcept;
        [[nodiscard]] HANDLE release() noexcept;
        void reset(HANDLE value = INVALID_HANDLE_VALUE) noexcept;

    private:
        HANDLE value_ = INVALID_HANDLE_VALUE;
    };

    [[noreturn]] void throw_last_error(std::string_view operation, DWORD error = GetLastError());
    [[noreturn]] void throw_ntstatus(std::string_view operation, NTSTATUS status);

    std::wstring utf8_to_wide(std::string_view value);
    std::string wide_to_utf8(std::wstring_view value);
    std::string trim_ascii(std::string value);

    bytes read_file(const std::filesystem::path& path, std::size_t maximum_bytes);
    void write_file_atomic(const std::filesystem::path& path, std::span<const std::uint8_t> content);
    std::filesystem::path executable_path();
    std::filesystem::path local_app_data_path();

    std::string base64_encode(std::span<const std::uint8_t> value);
    bytes base64_decode(std::string_view value, std::size_t minimum, std::size_t maximum);
    std::string hex_encode(std::span<const std::uint8_t> value);
    bytes hex_decode(std::string_view value, std::size_t expected_size);
    std::string json_escape(std::string_view value);

    std::string json_string(std::string_view document, std::string_view key);
    std::int64_t json_integer(std::string_view document, std::string_view key);

    bytes random_bytes(std::size_t size);
    bytes sha256(std::span<const std::uint8_t> value);
    bytes hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> value);
    bool verify_p256(
        std::span<const std::uint8_t> public_key_sec1,
        std::span<const std::uint8_t> message,
        std::span<const std::uint8_t> signature);

    class device_key
    {
    public:
        device_key() noexcept;
        device_key(device_key&&) noexcept;
        device_key& operator=(device_key&&) noexcept;
        device_key(const device_key&) = delete;
        device_key& operator=(const device_key&) = delete;
        ~device_key();

        static device_key load_or_create(std::string_view loader_id);
        [[nodiscard]] bytes public_key_sec1() const;
        [[nodiscard]] bytes sign(std::span<const std::uint8_t> message) const;

    private:
        struct implementation;
        explicit device_key(std::unique_ptr<implementation> implementation) noexcept;
        std::unique_ptr<implementation> implementation_;
    };

    class ecdh_key
    {
    public:
        ecdh_key();
        ecdh_key(ecdh_key&&) noexcept;
        ecdh_key& operator=(ecdh_key&&) noexcept;
        ecdh_key(const ecdh_key&) = delete;
        ecdh_key& operator=(const ecdh_key&) = delete;
        ~ecdh_key();

        [[nodiscard]] bytes public_key_sec1() const;
        [[nodiscard]] bytes derive(std::span<const std::uint8_t> peer_public_key_sec1) const;

    private:
        struct implementation;
        std::unique_ptr<implementation> implementation_;
    };

    bytes hkdf_sha256(
        std::span<const std::uint8_t> input_key_material,
        std::span<const std::uint8_t> salt,
        std::span<const std::uint8_t> info,
        std::size_t output_size);

    bytes aes_256_gcm_decrypt(
        std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> nonce,
        std::span<const std::uint8_t> ciphertext_and_tag,
        std::span<const std::uint8_t> additional_data,
        std::size_t expected_plaintext_size);

    void secure_clear(bytes& value) noexcept;

    struct http_response
    {
        DWORD status = 0;
        bytes body;
        std::map<std::string, std::string, std::less<>> headers;

        [[nodiscard]] std::string text() const;
        [[nodiscard]] std::string header(std::string_view name) const;
    };

    class http_client
    {
    public:
        explicit http_client(std::string base_url);
        http_client(http_client&&) noexcept;
        http_client& operator=(http_client&&) noexcept;
        http_client(const http_client&) = delete;
        http_client& operator=(const http_client&) = delete;
        ~http_client();

        [[nodiscard]] http_response get(std::string_view path, std::size_t maximum_response_bytes) const;
        [[nodiscard]] http_response post_json(
            std::string_view path,
            std::string_view body,
            std::string_view bearer_token,
            std::size_t maximum_response_bytes,
            std::span<const std::string_view> response_headers = {}) const;

    private:
        struct implementation;
        std::unique_ptr<implementation> implementation_;
    };
}
