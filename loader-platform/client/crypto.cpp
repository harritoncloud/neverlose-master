#include "common.hpp"

#include <ncrypt.h>
#include <sddl.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <optional>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

namespace nl
{
    namespace
    {
        class algorithm_handle
        {
        public:
            algorithm_handle() = default;
            explicit algorithm_handle(BCRYPT_ALG_HANDLE value) : value_(value) {}
            algorithm_handle(const algorithm_handle&) = delete;
            algorithm_handle& operator=(const algorithm_handle&) = delete;
            algorithm_handle(algorithm_handle&& other) noexcept : value_(other.release()) {}
            algorithm_handle& operator=(algorithm_handle&& other) noexcept
            {
                if (this != &other)
                    reset(other.release());
                return *this;
            }
            ~algorithm_handle() { reset(); }
            [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept { return value_; }
            [[nodiscard]] BCRYPT_ALG_HANDLE release() noexcept
            {
                const auto value = value_;
                value_ = nullptr;
                return value;
            }
            void reset(BCRYPT_ALG_HANDLE value = nullptr) noexcept
            {
                if (value_)
                    BCryptCloseAlgorithmProvider(value_, 0);
                value_ = value;
            }

        private:
            BCRYPT_ALG_HANDLE value_ = nullptr;
        };

        class key_handle
        {
        public:
            key_handle() = default;
            explicit key_handle(BCRYPT_KEY_HANDLE value) : value_(value) {}
            key_handle(const key_handle&) = delete;
            key_handle& operator=(const key_handle&) = delete;
            key_handle(key_handle&& other) noexcept : value_(other.release()) {}
            key_handle& operator=(key_handle&& other) noexcept
            {
                if (this != &other)
                    reset(other.release());
                return *this;
            }
            ~key_handle() { reset(); }
            [[nodiscard]] BCRYPT_KEY_HANDLE get() const noexcept { return value_; }
            [[nodiscard]] BCRYPT_KEY_HANDLE release() noexcept
            {
                const auto value = value_;
                value_ = nullptr;
                return value;
            }
            void reset(BCRYPT_KEY_HANDLE value = nullptr) noexcept
            {
                if (value_)
                    BCryptDestroyKey(value_);
                value_ = value;
            }

        private:
            BCRYPT_KEY_HANDLE value_ = nullptr;
        };

        class ncrypt_provider_handle
        {
        public:
            ncrypt_provider_handle() = default;
            explicit ncrypt_provider_handle(const NCRYPT_PROV_HANDLE value) : value_(value) {}
            ncrypt_provider_handle(const ncrypt_provider_handle&) = delete;
            ncrypt_provider_handle& operator=(const ncrypt_provider_handle&) = delete;
            ncrypt_provider_handle(ncrypt_provider_handle&& other) noexcept : value_(other.release()) {}
            ncrypt_provider_handle& operator=(ncrypt_provider_handle&& other) noexcept
            {
                if (this != &other)
                    reset(other.release());
                return *this;
            }
            ~ncrypt_provider_handle() { reset(); }
            [[nodiscard]] NCRYPT_PROV_HANDLE get() const noexcept { return value_; }
            [[nodiscard]] NCRYPT_PROV_HANDLE release() noexcept
            {
                const auto value = value_;
                value_ = 0;
                return value;
            }
            void reset(const NCRYPT_PROV_HANDLE value = 0) noexcept
            {
                if (value_)
                    NCryptFreeObject(value_);
                value_ = value;
            }

        private:
            NCRYPT_PROV_HANDLE value_ = 0;
        };

        class ncrypt_key_handle
        {
        public:
            ncrypt_key_handle() = default;
            explicit ncrypt_key_handle(const NCRYPT_KEY_HANDLE value) : value_(value) {}
            ncrypt_key_handle(const ncrypt_key_handle&) = delete;
            ncrypt_key_handle& operator=(const ncrypt_key_handle&) = delete;
            ncrypt_key_handle(ncrypt_key_handle&& other) noexcept : value_(other.release()) {}
            ncrypt_key_handle& operator=(ncrypt_key_handle&& other) noexcept
            {
                if (this != &other)
                    reset(other.release());
                return *this;
            }
            ~ncrypt_key_handle() { reset(); }
            [[nodiscard]] NCRYPT_KEY_HANDLE get() const noexcept { return value_; }
            [[nodiscard]] NCRYPT_KEY_HANDLE release() noexcept
            {
                const auto value = value_;
                value_ = 0;
                return value;
            }
            void reset(const NCRYPT_KEY_HANDLE value = 0) noexcept
            {
                if (value_)
                    NCryptFreeObject(value_);
                value_ = value;
            }

        private:
            NCRYPT_KEY_HANDLE value_ = 0;
        };

        class registry_handle
        {
        public:
            registry_handle() = default;
            explicit registry_handle(const HKEY value) : value_(value) {}
            registry_handle(const registry_handle&) = delete;
            registry_handle& operator=(const registry_handle&) = delete;
            registry_handle(registry_handle&& other) noexcept : value_(other.release()) {}
            registry_handle& operator=(registry_handle&& other) noexcept
            {
                if (this != &other)
                    reset(other.release());
                return *this;
            }
            ~registry_handle() { reset(); }
            [[nodiscard]] HKEY get() const noexcept { return value_; }
            [[nodiscard]] HKEY release() noexcept
            {
                const auto value = value_;
                value_ = nullptr;
                return value;
            }
            void reset(const HKEY value = nullptr) noexcept
            {
                if (value_)
                    RegCloseKey(value_);
                value_ = value;
            }

        private:
            HKEY value_ = nullptr;
        };

        class hash_handle
        {
        public:
            explicit hash_handle(BCRYPT_HASH_HANDLE value = nullptr) : value_(value) {}
            hash_handle(const hash_handle&) = delete;
            hash_handle& operator=(const hash_handle&) = delete;
            ~hash_handle()
            {
                if (value_)
                    BCryptDestroyHash(value_);
            }
            [[nodiscard]] BCRYPT_HASH_HANDLE get() const noexcept { return value_; }

        private:
            BCRYPT_HASH_HANDLE value_ = nullptr;
        };

        class secret_handle
        {
        public:
            explicit secret_handle(BCRYPT_SECRET_HANDLE value = nullptr) : value_(value) {}
            secret_handle(const secret_handle&) = delete;
            secret_handle& operator=(const secret_handle&) = delete;
            ~secret_handle()
            {
                if (value_)
                    BCryptDestroySecret(value_);
            }
            [[nodiscard]] BCRYPT_SECRET_HANDLE get() const noexcept { return value_; }

        private:
            BCRYPT_SECRET_HANDLE value_ = nullptr;
        };

        void check_status(const NTSTATUS status, const std::string_view operation)
        {
            if (status < 0)
                throw_ntstatus(operation, status);
        }

        void check_security_status(const SECURITY_STATUS status, const std::string_view operation)
        {
            if (status != ERROR_SUCCESS)
                throw std::runtime_error(std::string(operation) + " failed with security status " +
                    std::to_string(static_cast<std::uint32_t>(status)));
        }

        algorithm_handle open_algorithm(const wchar_t* identifier, const ULONG flags = 0)
        {
            BCRYPT_ALG_HANDLE value = nullptr;
            check_status(BCryptOpenAlgorithmProvider(&value, identifier, nullptr, flags), "BCryptOpenAlgorithmProvider");
            return algorithm_handle(value);
        }

        DWORD get_dword_property(BCRYPT_HANDLE handle, const wchar_t* property)
        {
            DWORD value = 0;
            DWORD copied = 0;
            check_status(BCryptGetProperty(handle, property, reinterpret_cast<PUCHAR>(&value), sizeof(value), &copied, 0), "BCryptGetProperty");
            if (copied != sizeof(value))
                throw std::runtime_error("BCrypt property has an unexpected size");
            return value;
        }

        bytes hash_data(const wchar_t* algorithm, const std::span<const std::uint8_t> key, const std::span<const std::uint8_t> value)
        {
            const ULONG flags = key.empty() ? 0 : BCRYPT_ALG_HANDLE_HMAC_FLAG;
            auto provider = open_algorithm(algorithm, flags);
            const DWORD object_size = get_dword_property(provider.get(), BCRYPT_OBJECT_LENGTH);
            const DWORD digest_size = get_dword_property(provider.get(), BCRYPT_HASH_LENGTH);
            bytes object(object_size);
            BCRYPT_HASH_HANDLE raw_hash = nullptr;
            check_status(BCryptCreateHash(
                provider.get(),
                &raw_hash,
                object.data(),
                static_cast<ULONG>(object.size()),
                key.empty() ? nullptr : const_cast<PUCHAR>(key.data()),
                static_cast<ULONG>(key.size()),
                0), "BCryptCreateHash");
            hash_handle hash(raw_hash);
            if (!value.empty())
                check_status(BCryptHashData(hash.get(), const_cast<PUCHAR>(value.data()), static_cast<ULONG>(value.size()), 0), "BCryptHashData");
            bytes output(digest_size);
            check_status(BCryptFinishHash(hash.get(), output.data(), static_cast<ULONG>(output.size()), 0), "BCryptFinishHash");
            secure_clear(object);
            return output;
        }

        bytes make_public_blob(const std::span<const std::uint8_t> public_key_sec1, const ULONG magic)
        {
            if (public_key_sec1.size() != 65 || public_key_sec1[0] != 4)
                throw std::runtime_error("P-256 public key is invalid");
            BCRYPT_ECCKEY_BLOB header{};
            header.dwMagic = magic;
            header.cbKey = 32;
            bytes blob(sizeof(header) + 64);
            std::memcpy(blob.data(), &header, sizeof(header));
            std::memcpy(blob.data() + sizeof(header), public_key_sec1.data() + 1, 64);
            return blob;
        }

        key_handle import_key(BCRYPT_ALG_HANDLE provider, const wchar_t* blob_type, bytes& blob)
        {
            BCRYPT_KEY_HANDLE value = nullptr;
            check_status(BCryptImportKeyPair(provider, nullptr, blob_type, &value, blob.data(), static_cast<ULONG>(blob.size()), 0), "BCryptImportKeyPair");
            return key_handle(value);
        }

        bytes export_key(BCRYPT_KEY_HANDLE key, const wchar_t* blob_type)
        {
            ULONG size = 0;
            check_status(BCryptExportKey(key, nullptr, blob_type, nullptr, 0, &size, 0), "BCryptExportKey(size)");
            bytes output(size);
            check_status(BCryptExportKey(key, nullptr, blob_type, output.data(), static_cast<ULONG>(output.size()), &size, 0), "BCryptExportKey");
            output.resize(size);
            return output;
        }

        bytes public_blob_to_sec1(const bytes& blob, const ULONG expected_magic)
        {
            if (blob.size() != sizeof(BCRYPT_ECCKEY_BLOB) + 64)
                throw std::runtime_error("CNG public key blob has an unexpected size");
            BCRYPT_ECCKEY_BLOB header{};
            std::memcpy(&header, blob.data(), sizeof(header));
            if (header.dwMagic != expected_magic || header.cbKey != 32)
                throw std::runtime_error("CNG public key blob is invalid");
            bytes output(65);
            output[0] = 4;
            std::memcpy(output.data() + 1, blob.data() + sizeof(header), 64);
            return output;
        }

        bytes export_platform_key(const NCRYPT_KEY_HANDLE key, const wchar_t* blob_type)
        {
            DWORD size = 0;
            check_security_status(NCryptExportKey(key, 0, blob_type, nullptr, nullptr, 0, &size, NCRYPT_SILENT_FLAG),
                "NCryptExportKey(size)");
            bytes output(size);
            check_security_status(NCryptExportKey(key, 0, blob_type, nullptr, output.data(),
                static_cast<DWORD>(output.size()), &size, NCRYPT_SILENT_FLAG), "NCryptExportKey");
            output.resize(size);
            return output;
        }

        struct platform_key_handles
        {
            ncrypt_provider_handle provider;
            ncrypt_key_handle key;
        };

        bool is_platform_key_name(const std::string_view value)
        {
            constexpr std::string_view prefix = "patchwin-device-";
            if (!value.starts_with(prefix) || value.size() != prefix.size() + 32)
                return false;
            return std::all_of(value.begin() + static_cast<std::ptrdiff_t>(prefix.size()), value.end(), [](const char character)
            {
                return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
            });
        }

        bool is_hardware_provider(const NCRYPT_PROV_HANDLE provider)
        {
            DWORD implementation_type = 0;
            DWORD copied = 0;
            if (NCryptGetProperty(provider, NCRYPT_IMPL_TYPE_PROPERTY,
                reinterpret_cast<PBYTE>(&implementation_type), sizeof(implementation_type), &copied, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
                return false;
            return copied == sizeof(implementation_type) && (implementation_type & NCRYPT_IMPL_HARDWARE_FLAG) != 0;
        }

        void delete_persisted_key(ncrypt_key_handle& key) noexcept
        {
            const NCRYPT_KEY_HANDLE value = key.release();
            if (!value)
                return;
            if (NCryptDeleteKey(value, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
                NCryptFreeObject(value);
        }

        void validate_platform_key(const NCRYPT_KEY_HANDLE key)
        {
            DWORD export_policy = 0;
            DWORD copied = 0;
            check_security_status(NCryptGetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY,
                reinterpret_cast<PBYTE>(&export_policy), sizeof(export_policy), &copied, NCRYPT_SILENT_FLAG),
                "NCryptGetProperty(export policy)");
            if (copied != sizeof(export_policy) || export_policy != 0)
                throw std::runtime_error("Platform device key is exportable");

            DWORD usage = 0;
            check_security_status(NCryptGetProperty(key, NCRYPT_KEY_USAGE_PROPERTY,
                reinterpret_cast<PBYTE>(&usage), sizeof(usage), &copied, NCRYPT_SILENT_FLAG),
                "NCryptGetProperty(key usage)");
            if (copied != sizeof(usage) || usage != NCRYPT_ALLOW_SIGNING_FLAG)
                throw std::runtime_error("Platform device key has an invalid usage policy");

            const bytes public_blob = export_platform_key(key, BCRYPT_ECCPUBLIC_BLOB);
            (void)public_blob_to_sec1(public_blob, BCRYPT_ECDSA_PUBLIC_P256_MAGIC);
        }

        platform_key_handles open_platform_key(const std::wstring& key_name)
        {
            NCRYPT_PROV_HANDLE raw_provider = 0;
            check_security_status(NCryptOpenStorageProvider(&raw_provider, MS_PLATFORM_CRYPTO_PROVIDER, 0),
                "NCryptOpenStorageProvider");
            platform_key_handles handles;
            handles.provider = ncrypt_provider_handle(raw_provider);
            if (!is_hardware_provider(handles.provider.get()))
                throw std::runtime_error("The platform crypto provider is not hardware-backed");

            NCRYPT_KEY_HANDLE raw_key = 0;
            check_security_status(NCryptOpenKey(handles.provider.get(), &raw_key, key_name.c_str(), 0,
                NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG),
                "NCryptOpenKey");
            handles.key = ncrypt_key_handle(raw_key);
            validate_platform_key(handles.key.get());
            return handles;
        }

        std::optional<platform_key_handles> try_create_platform_key(const std::wstring& key_name)
        {
            NCRYPT_PROV_HANDLE raw_provider = 0;
            if (NCryptOpenStorageProvider(&raw_provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) != ERROR_SUCCESS)
                return std::nullopt;

            platform_key_handles handles;
            handles.provider = ncrypt_provider_handle(raw_provider);
            if (!is_hardware_provider(handles.provider.get()))
                return std::nullopt;

            NCRYPT_KEY_HANDLE raw_key = 0;
            if (NCryptCreatePersistedKey(handles.provider.get(), &raw_key, NCRYPT_ECDSA_P256_ALGORITHM,
                key_name.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
                return std::nullopt;
            handles.key = ncrypt_key_handle(raw_key);

            try
            {
                DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG;
                check_security_status(NCryptSetProperty(handles.key.get(), NCRYPT_KEY_USAGE_PROPERTY,
                    reinterpret_cast<PBYTE>(&usage), sizeof(usage), 0), "NCryptSetProperty(key usage)");
                DWORD export_policy = 0;
                check_security_status(NCryptSetProperty(handles.key.get(), NCRYPT_EXPORT_POLICY_PROPERTY,
                    reinterpret_cast<PBYTE>(&export_policy), sizeof(export_policy), 0), "NCryptSetProperty(export policy)");
                check_security_status(NCryptFinalizeKey(handles.key.get(), NCRYPT_SILENT_FLAG), "NCryptFinalizeKey");
                validate_platform_key(handles.key.get());
                return handles;
            }
            catch (...)
            {
                delete_persisted_key(handles.key);
                return std::nullopt;
            }
        }

        bytes dpapi_protect(const std::span<const std::uint8_t> plaintext, const std::span<const std::uint8_t> entropy)
        {
            DATA_BLOB input{static_cast<DWORD>(plaintext.size()), const_cast<BYTE*>(plaintext.data())};
            DATA_BLOB optional_entropy{static_cast<DWORD>(entropy.size()), const_cast<BYTE*>(entropy.data())};
            DATA_BLOB output{};
            if (!CryptProtectData(&input, L"NL loader device key", &optional_entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output))
                throw_last_error("CryptProtectData");
            bytes result(output.pbData, output.pbData + output.cbData);
            SecureZeroMemory(output.pbData, output.cbData);
            LocalFree(output.pbData);
            return result;
        }

        bytes dpapi_unprotect(const std::span<const std::uint8_t> ciphertext, const std::span<const std::uint8_t> entropy)
        {
            DATA_BLOB input{static_cast<DWORD>(ciphertext.size()), const_cast<BYTE*>(ciphertext.data())};
            DATA_BLOB optional_entropy{static_cast<DWORD>(entropy.size()), const_cast<BYTE*>(entropy.data())};
            DATA_BLOB output{};
            if (!CryptUnprotectData(&input, nullptr, &optional_entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output))
                throw std::runtime_error("Device credential cannot be opened. Request an HWID reset before replacing it.");
            bytes result(output.pbData, output.pbData + output.cbData);
            SecureZeroMemory(output.pbData, output.cbData);
            LocalFree(output.pbData);
            return result;
        }

        bytes device_entropy(const std::string_view loader_id)
        {
            const std::string input = "nl-loader-device-key-v1\nloader_id=" + std::string(loader_id) + "\n";
            return sha256(std::span(reinterpret_cast<const std::uint8_t*>(input.data()), input.size()));
        }

        bytes platform_marker_entropy(const std::string_view loader_id)
        {
            const std::string input = "nl-loader-platform-key-marker-v1\nloader_id=" + std::string(loader_id) + "\n";
            return sha256(std::span(reinterpret_cast<const std::uint8_t*>(input.data()), input.size()));
        }

        void validate_loader_id(const std::string_view loader_id)
        {
            for (const char character : loader_id)
            {
                if (!((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                    (character >= '0' && character <= '9') || character == '-' || character == '_'))
                    throw std::runtime_error("Loader ID contains an unsupported character");
            }
            if (loader_id.size() < 20 || loader_id.size() > 64)
                throw std::runtime_error("Loader ID has an invalid size");
        }

        std::filesystem::path legacy_device_key_path(const std::string_view loader_id)
        {
            return local_app_data_path() / L"patchwin.cc" / L"loader" / (L"device-" + utf8_to_wide(loader_id) + L".bin");
        }

        constexpr wchar_t kDeviceRegistryPath[] = L"SOFTWARE\\patchwin.cc\\loader\\devices";

        [[noreturn]] void throw_registry_error(const std::string_view operation, const LSTATUS status)
        {
            throw std::runtime_error(std::string(operation) + " failed with registry status " + std::to_string(status));
        }

        std::optional<bytes> read_device_credential(const std::string_view loader_id)
        {
            HKEY raw_key = nullptr;
            LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kDeviceRegistryPath, 0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY, &raw_key);
            if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
                return std::nullopt;
            if (status != ERROR_SUCCESS)
                throw_registry_error("RegOpenKeyExW(device credential)", status);
            registry_handle key(raw_key);

            const std::wstring value_name = utf8_to_wide(loader_id);
            DWORD type = 0;
            DWORD size = 0;
            status = RegQueryValueExW(key.get(), value_name.c_str(), nullptr, &type, nullptr, &size);
            if (status == ERROR_FILE_NOT_FOUND)
                return std::nullopt;
            if (status != ERROR_SUCCESS)
                throw_registry_error("RegQueryValueExW(device credential size)", status);
            if (type != REG_BINARY || size <= 5 || size > (16u << 10))
                throw std::runtime_error("Stored device credential has an invalid format");

            bytes value(size);
            status = RegQueryValueExW(key.get(), value_name.c_str(), nullptr, &type, value.data(), &size);
            if (status != ERROR_SUCCESS)
                throw_registry_error("RegQueryValueExW(device credential)", status);
            if (type != REG_BINARY || size != value.size())
                throw std::runtime_error("Stored device credential changed while it was read");
            return value;
        }

        void protect_device_registry_key(const HKEY key)
        {
            PSECURITY_DESCRIPTOR descriptor = nullptr;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
                throw_last_error("ConvertStringSecurityDescriptorToSecurityDescriptorW(device credential)");
            const LSTATUS status = RegSetKeySecurity(key,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
                PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor);
            LocalFree(descriptor);
            if (status != ERROR_SUCCESS)
                throw_registry_error("RegSetKeySecurity(device credential)", status);
        }

        void write_device_credential(const std::string_view loader_id, const std::span<const std::uint8_t> value)
        {
            if (value.size() <= 5 || value.size() > (16u << 10))
                throw std::runtime_error("Device credential has an invalid size");

            HKEY raw_key = nullptr;
            DWORD disposition = 0;
            const LSTATUS create_status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kDeviceRegistryPath, 0, nullptr,
                REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | WRITE_DAC | WRITE_OWNER | KEY_WOW64_64KEY,
                nullptr, &raw_key, &disposition);
            if (create_status != ERROR_SUCCESS)
                throw_registry_error("RegCreateKeyExW(device credential)", create_status);
            registry_handle key(raw_key);
            protect_device_registry_key(key.get());

            const std::wstring value_name = utf8_to_wide(loader_id);
            const LSTATUS write_status = RegSetValueExW(key.get(), value_name.c_str(), 0, REG_BINARY,
                value.data(), static_cast<DWORD>(value.size()));
            if (write_status != ERROR_SUCCESS)
                throw_registry_error("RegSetValueExW(device credential)", write_status);
            const LSTATUS flush_status = RegFlushKey(key.get());
            if (flush_status != ERROR_SUCCESS)
                throw_registry_error("RegFlushKey(device credential)", flush_status);
        }
    }

    bytes random_bytes(const std::size_t size)
    {
        if (size > std::numeric_limits<ULONG>::max())
            throw std::runtime_error("Random request is too large");
        bytes output(size);
        if (!output.empty())
            check_status(BCryptGenRandom(nullptr, output.data(), static_cast<ULONG>(output.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG), "BCryptGenRandom");
        return output;
    }

    bytes sha256(const std::span<const std::uint8_t> value)
    {
        return hash_data(BCRYPT_SHA256_ALGORITHM, {}, value);
    }

    bytes hmac_sha256(const std::span<const std::uint8_t> key, const std::span<const std::uint8_t> value)
    {
        if (key.empty())
            throw std::runtime_error("HMAC key cannot be empty");
        return hash_data(BCRYPT_SHA256_ALGORITHM, key, value);
    }

    bool verify_p256(
        const std::span<const std::uint8_t> public_key_sec1,
        const std::span<const std::uint8_t> message,
        const std::span<const std::uint8_t> signature)
    {
        if (signature.size() != 64)
            return false;
        try
        {
            auto provider = open_algorithm(BCRYPT_ECDSA_P256_ALGORITHM);
            bytes blob = make_public_blob(public_key_sec1, BCRYPT_ECDSA_PUBLIC_P256_MAGIC);
            auto key = import_key(provider.get(), BCRYPT_ECCPUBLIC_BLOB, blob);
            bytes digest = sha256(message);
            const NTSTATUS status = BCryptVerifySignature(
                key.get(),
                nullptr,
                digest.data(),
                static_cast<ULONG>(digest.size()),
                const_cast<PUCHAR>(signature.data()),
                static_cast<ULONG>(signature.size()),
                0);
            return status >= 0;
        }
        catch (...)
        {
            return false;
        }
    }

    struct device_key::implementation
    {
        enum class backend
        {
            software,
            platform
        };

        backend storage = backend::software;
        algorithm_handle software_provider;
        key_handle software_key;
        ncrypt_provider_handle platform_provider;
        ncrypt_key_handle platform_key;
    };

    device_key::device_key() noexcept = default;
    device_key::device_key(std::unique_ptr<implementation> implementation) noexcept : implementation_(std::move(implementation)) {}
    device_key::device_key(device_key&&) noexcept = default;
    device_key& device_key::operator=(device_key&&) noexcept = default;
    device_key::~device_key() = default;

    device_key device_key::load_or_create(const std::string_view loader_id)
    {
        validate_loader_id(loader_id);
        auto implementation = std::make_unique<struct implementation>();
        std::optional<bytes> stored_credential = read_device_credential(loader_id);
        bool migrate_legacy_credential = false;
        if (!stored_credential)
        {
            const auto legacy_path = legacy_device_key_path(loader_id);
            std::error_code file_error;
            const bool legacy_exists = std::filesystem::exists(legacy_path, file_error);
            if (file_error)
                throw std::runtime_error("Unable to inspect the legacy device credential file");
            if (legacy_exists)
            {
                stored_credential = read_file(legacy_path, 16 << 10);
                migrate_legacy_credential = true;
            }
        }

        if (stored_credential)
        {
            const bytes& file = *stored_credential;
            constexpr std::array<std::uint8_t, 5> software_magic{'N', 'L', 'D', 'K', '1'};
            constexpr std::array<std::uint8_t, 5> platform_magic{'N', 'L', 'D', 'K', '2'};
            if (file.size() <= software_magic.size())
                throw std::runtime_error("Device credential file is invalid. Request an HWID reset before replacing it.");

            if (std::equal(software_magic.begin(), software_magic.end(), file.begin()))
            {
                implementation->software_provider = open_algorithm(BCRYPT_ECDSA_P256_ALGORITHM);
                bytes entropy = device_entropy(loader_id);
                bytes private_blob = dpapi_unprotect(std::span(file).subspan(software_magic.size()), entropy);
                secure_clear(entropy);
                try
                {
                    if (private_blob.size() != sizeof(BCRYPT_ECCKEY_BLOB) + 96)
                        throw std::runtime_error("Device credential has an invalid key size");
                    BCRYPT_ECCKEY_BLOB header{};
                    std::memcpy(&header, private_blob.data(), sizeof(header));
                    if (header.dwMagic != BCRYPT_ECDSA_PRIVATE_P256_MAGIC || header.cbKey != 32)
                        throw std::runtime_error("Device credential has an invalid key format");
                    implementation->software_key = import_key(implementation->software_provider.get(), BCRYPT_ECCPRIVATE_BLOB, private_blob);
                    secure_clear(private_blob);
                }
                catch (...)
                {
                    secure_clear(private_blob);
                    throw;
                }
            }
            else if (std::equal(platform_magic.begin(), platform_magic.end(), file.begin()))
            {
                bytes entropy = platform_marker_entropy(loader_id);
                bytes marker = dpapi_unprotect(std::span(file).subspan(platform_magic.size()), entropy);
                secure_clear(entropy);
                const std::string key_name(marker.begin(), marker.end());
                secure_clear(marker);
                if (!is_platform_key_name(key_name))
                    throw std::runtime_error("Platform device credential marker is invalid. Request an HWID reset before replacing it.");
                try
                {
                    platform_key_handles handles = open_platform_key(utf8_to_wide(key_name));
                    implementation->platform_provider = std::move(handles.provider);
                    implementation->platform_key = std::move(handles.key);
                    implementation->storage = implementation::backend::platform;
                }
                catch (...)
                {
                    throw std::runtime_error("Platform device credential cannot be opened. Request an HWID reset before replacing it.");
                }
            }
            else
                throw std::runtime_error("Device credential file is invalid. Request an HWID reset before replacing it.");

            if (migrate_legacy_credential)
                write_device_credential(loader_id, file);
        }
        else
        {
            bytes name_random = random_bytes(16);
            const std::string key_name = "patchwin-device-" + hex_encode(name_random);
            secure_clear(name_random);
            if (auto handles = try_create_platform_key(utf8_to_wide(key_name)))
            {
                try
                {
                    bytes entropy = platform_marker_entropy(loader_id);
                    const bytes marker(key_name.begin(), key_name.end());
                    bytes protected_marker = dpapi_protect(marker, entropy);
                    secure_clear(entropy);
                    constexpr std::array<std::uint8_t, 5> magic{'N', 'L', 'D', 'K', '2'};
                    bytes file(magic.begin(), magic.end());
                    file.insert(file.end(), protected_marker.begin(), protected_marker.end());
                    write_device_credential(loader_id, file);
                    secure_clear(protected_marker);
                    secure_clear(file);
                    implementation->platform_provider = std::move(handles->provider);
                    implementation->platform_key = std::move(handles->key);
                    implementation->storage = implementation::backend::platform;
                    return device_key(std::move(implementation));
                }
                catch (...)
                {
                    delete_persisted_key(handles->key);
                    throw;
                }
            }

            implementation->software_provider = open_algorithm(BCRYPT_ECDSA_P256_ALGORITHM);
            BCRYPT_KEY_HANDLE raw_key = nullptr;
            check_status(BCryptGenerateKeyPair(implementation->software_provider.get(), &raw_key, 256, 0), "BCryptGenerateKeyPair");
            implementation->software_key = key_handle(raw_key);
            check_status(BCryptFinalizeKeyPair(implementation->software_key.get(), 0), "BCryptFinalizeKeyPair");
            bytes private_blob = export_key(implementation->software_key.get(), BCRYPT_ECCPRIVATE_BLOB);
            try
            {
                bytes entropy = device_entropy(loader_id);
                bytes protected_blob = dpapi_protect(private_blob, entropy);
                secure_clear(entropy);
                constexpr std::array<std::uint8_t, 5> magic{'N', 'L', 'D', 'K', '1'};
                bytes file(magic.begin(), magic.end());
                file.insert(file.end(), protected_blob.begin(), protected_blob.end());
                write_device_credential(loader_id, file);
                secure_clear(private_blob);
                secure_clear(protected_blob);
                secure_clear(file);
            }
            catch (...)
            {
                secure_clear(private_blob);
                throw;
            }
        }
        return device_key(std::move(implementation));
    }

    bytes device_key::public_key_sec1() const
    {
        if (!implementation_)
            throw std::runtime_error("Device key is not initialized");
        if (implementation_->storage == implementation::backend::platform)
            return public_blob_to_sec1(export_platform_key(implementation_->platform_key.get(), BCRYPT_ECCPUBLIC_BLOB),
                BCRYPT_ECDSA_PUBLIC_P256_MAGIC);
        return public_blob_to_sec1(export_key(implementation_->software_key.get(), BCRYPT_ECCPUBLIC_BLOB),
            BCRYPT_ECDSA_PUBLIC_P256_MAGIC);
    }

    bytes device_key::sign(const std::span<const std::uint8_t> message) const
    {
        if (!implementation_)
            throw std::runtime_error("Device key is not initialized");
        bytes digest = sha256(message);
        DWORD signature_size = 0;
        bytes signature;
        if (implementation_->storage == implementation::backend::platform)
        {
            check_security_status(NCryptSignHash(implementation_->platform_key.get(), nullptr, digest.data(),
                static_cast<DWORD>(digest.size()), nullptr, 0, &signature_size, NCRYPT_SILENT_FLAG), "NCryptSignHash(size)");
            signature.resize(signature_size);
            check_security_status(NCryptSignHash(implementation_->platform_key.get(), nullptr, digest.data(),
                static_cast<DWORD>(digest.size()), signature.data(), static_cast<DWORD>(signature.size()),
                &signature_size, NCRYPT_SILENT_FLAG), "NCryptSignHash");
        }
        else
        {
            check_status(BCryptSignHash(implementation_->software_key.get(), nullptr, digest.data(),
                static_cast<ULONG>(digest.size()), nullptr, 0, &signature_size, 0), "BCryptSignHash(size)");
            signature.resize(signature_size);
            check_status(BCryptSignHash(implementation_->software_key.get(), nullptr, digest.data(),
                static_cast<ULONG>(digest.size()), signature.data(), static_cast<ULONG>(signature.size()),
                &signature_size, 0), "BCryptSignHash");
        }
        signature.resize(signature_size);
        if (signature.size() != 64)
            throw std::runtime_error("Device signature has an unexpected size");
        return signature;
    }

    struct ecdh_key::implementation
    {
        algorithm_handle provider;
        key_handle key;
    };

    ecdh_key::ecdh_key() : implementation_(std::make_unique<struct implementation>())
    {
        implementation_->provider = open_algorithm(BCRYPT_ECDH_P256_ALGORITHM);
        BCRYPT_KEY_HANDLE raw_key = nullptr;
        check_status(BCryptGenerateKeyPair(implementation_->provider.get(), &raw_key, 256, 0), "BCryptGenerateKeyPair(ECDH)");
        implementation_->key = key_handle(raw_key);
        check_status(BCryptFinalizeKeyPair(implementation_->key.get(), 0), "BCryptFinalizeKeyPair(ECDH)");
    }

    ecdh_key::ecdh_key(ecdh_key&&) noexcept = default;
    ecdh_key& ecdh_key::operator=(ecdh_key&&) noexcept = default;
    ecdh_key::~ecdh_key() = default;

    bytes ecdh_key::public_key_sec1() const
    {
        return public_blob_to_sec1(export_key(implementation_->key.get(), BCRYPT_ECCPUBLIC_BLOB), BCRYPT_ECDH_PUBLIC_P256_MAGIC);
    }

    bytes ecdh_key::derive(const std::span<const std::uint8_t> peer_public_key_sec1) const
    {
        bytes blob = make_public_blob(peer_public_key_sec1, BCRYPT_ECDH_PUBLIC_P256_MAGIC);
        auto peer = import_key(implementation_->provider.get(), BCRYPT_ECCPUBLIC_BLOB, blob);
        BCRYPT_SECRET_HANDLE raw_secret = nullptr;
        check_status(BCryptSecretAgreement(implementation_->key.get(), peer.get(), &raw_secret, 0), "BCryptSecretAgreement");
        secret_handle secret(raw_secret);
        ULONG size = 0;
        check_status(BCryptDeriveKey(secret.get(), BCRYPT_KDF_RAW_SECRET, nullptr, nullptr, 0, &size, 0), "BCryptDeriveKey(size)");
        bytes shared(size);
        check_status(BCryptDeriveKey(secret.get(), BCRYPT_KDF_RAW_SECRET, nullptr, shared.data(), static_cast<ULONG>(shared.size()), &size, 0), "BCryptDeriveKey");
        shared.resize(size);
        // CNG exposes this KDF output little-endian; Go's ECDH API uses big-endian bytes.
        std::reverse(shared.begin(), shared.end());
        return shared;
    }

    bytes hkdf_sha256(
        const std::span<const std::uint8_t> input_key_material,
        const std::span<const std::uint8_t> salt,
        const std::span<const std::uint8_t> info,
        const std::size_t output_size)
    {
        constexpr std::size_t digest_size = 32;
        if (output_size == 0 || output_size > 255 * digest_size)
            throw std::runtime_error("HKDF output size is invalid");
        bytes effective_salt;
        if (salt.empty())
            effective_salt.assign(digest_size, 0);
        else
            effective_salt.assign(salt.begin(), salt.end());
        bytes pseudorandom_key = hmac_sha256(effective_salt, input_key_material);
        bytes output;
        output.reserve(output_size);
        bytes previous;
        for (std::uint16_t counter = 1; output.size() < output_size; ++counter)
        {
            bytes block_input;
            block_input.reserve(previous.size() + info.size() + 1);
            block_input.insert(block_input.end(), previous.begin(), previous.end());
            block_input.insert(block_input.end(), info.begin(), info.end());
            block_input.push_back(static_cast<std::uint8_t>(counter));
            previous = hmac_sha256(pseudorandom_key, block_input);
            const std::size_t take = std::min(previous.size(), output_size - output.size());
            output.insert(output.end(), previous.begin(), previous.begin() + static_cast<std::ptrdiff_t>(take));
            secure_clear(block_input);
        }
        secure_clear(effective_salt);
        secure_clear(pseudorandom_key);
        secure_clear(previous);
        return output;
    }

    bytes aes_256_gcm_decrypt(
        const std::span<const std::uint8_t> key,
        const std::span<const std::uint8_t> nonce,
        const std::span<const std::uint8_t> ciphertext_and_tag,
        const std::span<const std::uint8_t> additional_data,
        const std::size_t expected_plaintext_size)
    {
        constexpr std::size_t tag_size = 16;
        if (key.size() != 32 || nonce.size() != 12 || ciphertext_and_tag.size() < tag_size ||
            ciphertext_and_tag.size() - tag_size != expected_plaintext_size)
            throw std::runtime_error("AES-GCM envelope has invalid sizes");
        auto provider = open_algorithm(BCRYPT_AES_ALGORITHM);
        check_status(BCryptSetProperty(
            provider.get(),
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_GCM)),
            0), "BCryptSetProperty(GCM)");
        const DWORD object_size = get_dword_property(provider.get(), BCRYPT_OBJECT_LENGTH);
        bytes object(object_size);
        BCRYPT_KEY_HANDLE raw_key = nullptr;
        check_status(BCryptGenerateSymmetricKey(
            provider.get(),
            &raw_key,
            object.data(),
            static_cast<ULONG>(object.size()),
            const_cast<PUCHAR>(key.data()),
            static_cast<ULONG>(key.size()),
            0), "BCryptGenerateSymmetricKey");
        key_handle symmetric_key(raw_key);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authentication{};
        BCRYPT_INIT_AUTH_MODE_INFO(authentication);
        authentication.pbNonce = const_cast<PUCHAR>(nonce.data());
        authentication.cbNonce = static_cast<ULONG>(nonce.size());
        authentication.pbAuthData = additional_data.empty() ? nullptr : const_cast<PUCHAR>(additional_data.data());
        authentication.cbAuthData = static_cast<ULONG>(additional_data.size());
        authentication.pbTag = const_cast<PUCHAR>(ciphertext_and_tag.data() + expected_plaintext_size);
        authentication.cbTag = tag_size;

        bytes plaintext(expected_plaintext_size);
        ULONG written = 0;
        check_status(BCryptDecrypt(
            symmetric_key.get(),
            const_cast<PUCHAR>(ciphertext_and_tag.data()),
            static_cast<ULONG>(expected_plaintext_size),
            &authentication,
            nullptr,
            0,
            plaintext.data(),
            static_cast<ULONG>(plaintext.size()),
            &written,
            0), "BCryptDecrypt(GCM)");
        if (written != plaintext.size())
            throw std::runtime_error("AES-GCM plaintext size does not match the manifest");
        secure_clear(object);
        return plaintext;
    }

    void secure_clear(bytes& value) noexcept
    {
        if (!value.empty())
            SecureZeroMemory(value.data(), value.size());
        value.clear();
    }
}
