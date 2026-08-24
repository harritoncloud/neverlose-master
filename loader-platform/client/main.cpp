#include "common.hpp"
#include "resource.h"

#include <sddl.h>
#include <winreg.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <optional>
#include <sstream>

#pragma comment(lib, "advapi32.lib")

namespace
{
    constexpr std::string_view kClientVersion = "1.6.0";
    constexpr std::string_view kFooterMagicV1 = "NLPERS01";
    constexpr std::string_view kFooterMagic = "NLPERS02";
    constexpr std::string_view kFooterMagicV3 = "NLPERS03";
    constexpr std::string_view kImageFooterMagic = "NLIMAGE1";
    constexpr std::string_view kServerPublicKey =
        "BKm2TleHfAHQPS+JBRp1x32YELUCNqRYPMGZjbAKR86K5sjoKrYSbE9Z1UUCWtug5/h545h8eC9WKZ5xImUDYb8";
    constexpr std::string_view kInjectorSHA256 =
        "f75f5944b47b219099180501d465dfa8a91604bb8b713756d0467d75699ead87";
    constexpr std::size_t kMaximumExecutableBytes = 65ull << 20;
    constexpr std::size_t kMaximumArtifactBytes = 256ull << 20;

    struct personalization
    {
        nl::bytes payload;
        nl::bytes signature;
        std::string audience;
        std::string loader_id;
        std::string enrollment_secret;
        std::string heartbeat_token;
        std::int64_t license_id = 0;
        std::int64_t issued_at = 0;
    };

    struct challenge
    {
        std::string nonce;
        std::int64_t expires_at = 0;
    };

    struct session
    {
        std::string access_token;
    };

    struct artifact_ticket
    {
        std::string token;
        std::string version;
        std::string sha256;
        std::int64_t size = 0;
    };

    struct integrity_incident
    {
        std::string component;
        std::string expected_sha256;
        std::string observed_sha256;
    };

    struct injector_run_result
    {
        int exit_code = 1;
        std::optional<integrity_incident> incident;
    };

    struct wipe_guard
    {
        nl::bytes* value = nullptr;
        ~wipe_guard()
        {
            if (value)
                nl::secure_clear(*value);
        }
    };

    void secure_clear_string(std::string& value) noexcept
    {
        if (!value.empty())
            SecureZeroMemory(value.data(), value.size());
        value.clear();
    }

    struct string_wipe_guard
    {
        std::string* value = nullptr;
        ~string_wipe_guard()
        {
            if (value)
                secure_clear_string(*value);
        }
    };

    bool valid_enrollment_secret(const std::string_view value)
    {
        if (value.size() < 20 || value.size() > 64)
            return false;
        return std::all_of(value.begin(), value.end(), [](const char character)
        {
            return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                (character >= '0' && character <= '9') || character == '-' || character == '_';
        });
    }

    std::int64_t unix_time()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    nl::win_handle acquire_loader_mutex(const std::string_view loader_id)
    {
        const std::wstring name = L"Local\\patchwin.cc-loader-" + nl::utf8_to_wide(loader_id);
        SetLastError(ERROR_SUCCESS);
        nl::win_handle mutex(CreateMutexW(nullptr, TRUE, name.c_str()));
        if (!mutex)
            nl::throw_last_error("CreateMutexW(loader)");
        if (GetLastError() == ERROR_ALREADY_EXISTS)
            throw std::runtime_error("This personal loader is already running in the current Windows session");
        return mutex;
    }

    std::uint32_t read_little_u32(const std::span<const std::uint8_t> value)
    {
        if (value.size() != 4)
            throw std::runtime_error("Invalid 32-bit field");
        return static_cast<std::uint32_t>(value[0]) |
            (static_cast<std::uint32_t>(value[1]) << 8) |
            (static_cast<std::uint32_t>(value[2]) << 16) |
            (static_cast<std::uint32_t>(value[3]) << 24);
    }

    std::vector<std::string> split_lines(const std::string_view value)
    {
        std::vector<std::string> lines;
        std::size_t start = 0;
        for (;;)
        {
            const std::size_t end = value.find('\n', start);
            if (end == std::string_view::npos)
            {
                lines.emplace_back(value.substr(start));
                break;
            }
            lines.emplace_back(value.substr(start, end - start));
            start = end + 1;
        }
        return lines;
    }

    std::int64_t parse_positive_integer(const std::string_view value, const std::string_view field)
    {
        std::int64_t result = 0;
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || result <= 0)
            throw std::runtime_error("Invalid " + std::string(field));
        return result;
    }

    personalization parse_certificate(nl::bytes payload, nl::bytes signature)
    {
        const nl::bytes server_public_key = nl::base64_decode(kServerPublicKey, 65, 65);
        if (!nl::verify_p256(server_public_key, payload, signature))
            throw std::runtime_error("Personal loader signature is invalid");
        const std::string text(reinterpret_cast<const char*>(payload.data()), payload.size());
        if (text.find('\r') != std::string::npos)
            throw std::runtime_error("Personal loader certificate is malformed");
        const auto lines = split_lines(text);
        if (lines.size() != 6 || lines[0] != "nl-loader-certificate-v1" || !lines[5].empty())
            throw std::runtime_error("Personal loader certificate has an unsupported format");

        constexpr std::string_view audience_prefix = "audience=";
        constexpr std::string_view loader_prefix = "loader_id=";
        constexpr std::string_view license_prefix = "license_id=";
        constexpr std::string_view issued_prefix = "issued_at=";
        if (!lines[1].starts_with(audience_prefix) || !lines[2].starts_with(loader_prefix) ||
            !lines[3].starts_with(license_prefix) || !lines[4].starts_with(issued_prefix))
            throw std::runtime_error("Personal loader certificate fields are invalid");

        personalization result;
        result.payload = std::move(payload);
        result.signature = std::move(signature);
        result.audience = lines[1].substr(audience_prefix.size());
        result.loader_id = lines[2].substr(loader_prefix.size());
        result.license_id = parse_positive_integer(std::string_view(lines[3]).substr(license_prefix.size()), "license ID");
        result.issued_at = parse_positive_integer(std::string_view(lines[4]).substr(issued_prefix.size()), "certificate timestamp");
        static_cast<void>(nl::base64_decode(result.loader_id, 18, 18));
        if (!result.audience.starts_with("https://") || result.audience.ends_with('/') ||
            result.audience.find('\r') != std::string::npos || result.audience.find('\n') != std::string::npos)
            throw std::runtime_error("Personal loader server URL is invalid");
        if (result.issued_at > unix_time() + 300)
            throw std::runtime_error("Personal loader certificate timestamp is in the future");
        return result;
    }

    std::optional<personalization> read_personalization()
    {
        const nl::bytes executable = nl::read_file(nl::executable_path(), kMaximumExecutableBytes);
        constexpr std::size_t image_trailer_size = 64 + 4 + kImageFooterMagic.size();
        if (executable.size() < image_trailer_size ||
            !std::equal(kImageFooterMagic.begin(), kImageFooterMagic.end(), executable.end() - static_cast<std::ptrdiff_t>(kImageFooterMagic.size())))
        {
            if (executable.size() >= kFooterMagic.size() &&
                (std::equal(kFooterMagic.begin(), kFooterMagic.end(), executable.end() - static_cast<std::ptrdiff_t>(kFooterMagic.size())) ||
                    std::equal(kFooterMagicV1.begin(), kFooterMagicV1.end(), executable.end() - static_cast<std::ptrdiff_t>(kFooterMagicV1.size()))))
                throw std::runtime_error("This personal loader is outdated. Download a fresh copy through Discord.");
            return std::nullopt;
        }

        const std::size_t image_magic_offset = executable.size() - kImageFooterMagic.size();
        const std::size_t image_length_offset = image_magic_offset - 4;
        const std::uint32_t manifest_size = read_little_u32(std::span(executable).subspan(image_length_offset, 4));
        if (manifest_size == 0 || manifest_size > 4096 || image_length_offset < 64 + manifest_size)
            throw std::runtime_error("Personal loader image footer is invalid");
        const std::size_t image_signature_offset = image_length_offset - 64;
        const std::size_t image_manifest_offset = image_signature_offset - manifest_size;
        const std::span<const std::uint8_t> manifest = std::span(executable).subspan(image_manifest_offset, manifest_size);
        const std::span<const std::uint8_t> image_signature = std::span(executable).subspan(image_signature_offset, 64);
        const nl::bytes server_public_key = nl::base64_decode(kServerPublicKey, 65, 65);
        if (!nl::verify_p256(server_public_key, manifest, image_signature))
            throw std::runtime_error("Personal loader image signature is invalid");

        const std::string manifest_text(reinterpret_cast<const char*>(manifest.data()), manifest.size());
        if (manifest_text.find('\r') != std::string::npos)
            throw std::runtime_error("Personal loader image manifest is malformed");
        const auto manifest_lines = split_lines(manifest_text);
        constexpr std::string_view image_size_prefix = "image_size=";
        constexpr std::string_view image_hash_prefix = "image_sha256=";
        if (manifest_lines.size() != 4 || manifest_lines[0] != "nl-loader-image-v1" || !manifest_lines[3].empty() ||
            !manifest_lines[1].starts_with(image_size_prefix) || !manifest_lines[2].starts_with(image_hash_prefix))
            throw std::runtime_error("Personal loader image manifest has an unsupported format");

        const std::int64_t protected_size = parse_positive_integer(
            std::string_view(manifest_lines[1]).substr(image_size_prefix.size()), "loader image size");
        if (protected_size != static_cast<std::int64_t>(image_manifest_offset))
            throw std::runtime_error("Personal loader image size does not match its manifest");
        const nl::bytes expected_hash = nl::hex_decode(
            std::string_view(manifest_lines[2]).substr(image_hash_prefix.size()), 32);
        const nl::bytes actual_hash = nl::sha256(std::span(executable).first(image_manifest_offset));
        if (actual_hash != expected_hash)
            throw std::runtime_error("Personal loader image integrity check failed");

        constexpr std::size_t minimum_trailer_size = 64 + 4 + kFooterMagic.size();
        if (image_manifest_offset < minimum_trailer_size)
            throw std::runtime_error("Personal loader certificate footer is missing");
        const std::size_t magic_offset = image_manifest_offset - kFooterMagic.size();
        const auto magic = executable.begin() + static_cast<std::ptrdiff_t>(magic_offset);
        const bool v3_format = std::equal(kFooterMagicV3.begin(), kFooterMagicV3.end(), magic);
        const bool current_format = std::equal(kFooterMagic.begin(), kFooterMagic.end(), magic);
        const bool legacy_format = std::equal(kFooterMagicV1.begin(), kFooterMagicV1.end(), magic);
        if (!v3_format && !current_format && !legacy_format)
            throw std::runtime_error("Personal loader certificate footer is invalid");

        std::size_t payload_length_offset = magic_offset - 4;
        std::size_t signature_end = payload_length_offset;
        std::string enrollment_secret;
        std::string heartbeat_token;
        string_wipe_guard enrollment_guard{&enrollment_secret};
        string_wipe_guard heartbeat_guard{&heartbeat_token};
        const auto extract_secret = [&](std::size_t& cursor, const std::uint32_t size, std::string& destination)
        {
            if (size < 20 || size > 64 || cursor < size + 64)
                throw std::runtime_error("Personal loader enrollment footer is invalid");
            const std::size_t offset = cursor - size;
            destination.assign(
                reinterpret_cast<const char*>(executable.data() + offset), size);
            if (!valid_enrollment_secret(destination))
                throw std::runtime_error("Personal loader enrollment secret is invalid");
            cursor = offset;
        };
        if (v3_format)
        {
            if (magic_offset < 12)
                throw std::runtime_error("Personal loader heartbeat footer is invalid");
            const std::uint32_t heartbeat_size = read_little_u32(
                std::span(executable).subspan(magic_offset - 4, 4));
            const std::uint32_t enrollment_size = read_little_u32(
                std::span(executable).subspan(magic_offset - 8, 4));
            payload_length_offset = magic_offset - 12;
            std::size_t cursor = payload_length_offset;
            extract_secret(cursor, heartbeat_size, heartbeat_token);
            extract_secret(cursor, enrollment_size, enrollment_secret);
            signature_end = cursor;
        }
        else if (current_format)
        {
            if (payload_length_offset < 4)
                throw std::runtime_error("Personal loader enrollment footer is invalid");
            const std::uint32_t enrollment_size = read_little_u32(
                std::span(executable).subspan(payload_length_offset, 4));
            payload_length_offset -= 4;
            std::size_t cursor = payload_length_offset;
            extract_secret(cursor, enrollment_size, enrollment_secret);
            signature_end = cursor;
        }

        const std::uint32_t payload_size = read_little_u32(
            std::span(executable).subspan(payload_length_offset, 4));
        if (payload_size == 0 || payload_size > 4096 || signature_end < 64 + payload_size)
            throw std::runtime_error("Personal loader footer is invalid");
        const std::size_t signature_offset = signature_end - 64;
        const std::size_t payload_offset = signature_offset - payload_size;
        nl::bytes payload(
            executable.begin() + static_cast<std::ptrdiff_t>(payload_offset),
            executable.begin() + static_cast<std::ptrdiff_t>(signature_offset));
        nl::bytes signature(
            executable.begin() + static_cast<std::ptrdiff_t>(signature_offset),
            executable.begin() + static_cast<std::ptrdiff_t>(signature_end));
        personalization result = parse_certificate(std::move(payload), std::move(signature));
        result.enrollment_secret = std::move(enrollment_secret);
        result.heartbeat_token = std::move(heartbeat_token);
        enrollment_guard.value = nullptr;
        heartbeat_guard.value = nullptr;
        return result;
    }

    nl::bytes embedded_injector()
    {
        const HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_INJECTOR), RT_RCDATA);
        if (!resource)
            nl::throw_last_error("FindResourceW(injector)");
        const DWORD size = SizeofResource(nullptr, resource);
        if (size < 1024 * 1024 || size > 32 * 1024 * 1024)
            throw std::runtime_error("Embedded injector has an invalid size");
        const HGLOBAL loaded = LoadResource(nullptr, resource);
        if (!loaded)
            nl::throw_last_error("LoadResource(injector)");
        const auto* data = static_cast<const std::uint8_t*>(LockResource(loaded));
        if (!data)
            nl::throw_last_error("LockResource(injector)");
        nl::bytes output(data, data + size);
        if (output.size() < 2 || output[0] != 'M' || output[1] != 'Z' || nl::hex_encode(nl::sha256(output)) != kInjectorSHA256)
            throw std::runtime_error("Embedded injector integrity check failed");
        return output;
    }

    std::wstring read_machine_guid()
    {
        HKEY raw_key = nullptr;
        const LSTATUS opened = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography",
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &raw_key);
        if (opened != ERROR_SUCCESS)
            nl::throw_last_error("RegOpenKeyExW(MachineGuid)", opened);
        struct key_closer
        {
            HKEY value;
            ~key_closer() { if (value) RegCloseKey(value); }
        } closer{raw_key};

        DWORD type = 0;
        DWORD size = 0;
        LSTATUS status = RegQueryValueExW(raw_key, L"MachineGuid", nullptr, &type, nullptr, &size);
        if (status != ERROR_SUCCESS)
            nl::throw_last_error("RegQueryValueExW(MachineGuid size)", status);
        if ((type != REG_SZ && type != REG_EXPAND_SZ) || size < sizeof(wchar_t) || size > 1024 ||
            size % sizeof(wchar_t) != 0)
            throw std::runtime_error("MachineGuid registry value is invalid");
        std::wstring value(size / sizeof(wchar_t), L'\0');
        status = RegQueryValueExW(raw_key, L"MachineGuid", nullptr, &type, reinterpret_cast<BYTE*>(value.data()), &size);
        if (status != ERROR_SUCCESS)
            nl::throw_last_error("RegQueryValueExW(MachineGuid)", status);
        if ((type != REG_SZ && type != REG_EXPAND_SZ) || size < sizeof(wchar_t) ||
            size > value.size() * sizeof(wchar_t) || size % sizeof(wchar_t) != 0)
            throw std::runtime_error("MachineGuid registry value changed while being read");
        value.resize(size / sizeof(wchar_t));
        while (!value.empty() && value.back() == L'\0')
            value.pop_back();
        if (value.empty())
            throw std::runtime_error("MachineGuid is empty");
        std::transform(value.begin(), value.end(), value.begin(), [](const wchar_t character)
        {
            return static_cast<wchar_t>(std::towlower(character));
        });
        return value;
    }

    std::string hardware_hash()
    {
        std::wstring windows_directory(32768, L'\0');
        const UINT length = GetWindowsDirectoryW(windows_directory.data(), static_cast<UINT>(windows_directory.size()));
        if (length == 0 || length >= windows_directory.size())
            nl::throw_last_error("GetWindowsDirectoryW");
        windows_directory.resize(length);
        if (windows_directory.size() < 3 || windows_directory[1] != L':')
            throw std::runtime_error("Windows system volume is invalid");
        const std::wstring root = windows_directory.substr(0, 3);
        DWORD serial = 0;
        if (!GetVolumeInformationW(root.c_str(), nullptr, 0, &serial, nullptr, nullptr, nullptr, 0))
            nl::throw_last_error("GetVolumeInformationW");

        char serial_text[9]{};
        std::snprintf(serial_text, sizeof(serial_text), "%08lx", static_cast<unsigned long>(serial));
        const std::string canonical =
            "nl-hwid-v1\nmachine_guid=" + nl::wide_to_utf8(read_machine_guid()) +
            "\nsystem_volume=" + serial_text + "\n";
        return nl::hex_encode(nl::sha256(std::span(
            reinterpret_cast<const std::uint8_t*>(canonical.data()), canonical.size())));
    }

    void require_status(const nl::http_response& response, const DWORD expected, const std::string_view operation)
    {
        if (response.status != expected)
            throw std::runtime_error(std::string(operation) + " failed (HTTP " + std::to_string(response.status) + ")");
    }

    challenge request_challenge(const nl::http_client& client, const std::string_view audience)
    {
        const nl::http_response response = client.get("/api/v1/challenge", 64 << 10);
        require_status(response, 200, "Server challenge");
        const std::string document = response.text();
        const std::string response_audience = nl::json_string(document, "audience");
        const std::string nonce = nl::json_string(document, "nonce");
        const std::int64_t expires_at = nl::json_integer(document, "expires_at");
        const nl::bytes signature = nl::base64_decode(nl::json_string(document, "signature"), 64, 64);
        const std::int64_t now = unix_time();
        if (response_audience != audience || expires_at <= now || expires_at > now + 120)
            throw std::runtime_error("Server challenge metadata is invalid");
        const std::string message =
            "nl-auth-challenge-v1\naudience=" + response_audience +
            "\nnonce=" + nonce +
            "\nexpires_at=" + std::to_string(expires_at) + "\n";
        if (!nl::verify_p256(
            nl::base64_decode(kServerPublicKey, 65, 65),
            std::span(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()),
            signature))
            throw std::runtime_error("Server challenge signature is invalid");
        return {nonce, expires_at};
    }

    std::string loader_auth_message(
        const personalization& certificate,
        const challenge& server_challenge,
        const std::string_view hwid,
        const nl::bytes& public_key,
        const std::string_view pairing_code,
        const std::string_view client_nonce)
    {
        return
            "nl-loader-auth-v2\naudience=" + certificate.audience +
            "\nchallenge=" + server_challenge.nonce +
            "\nloader_id=" + certificate.loader_id +
            "\ncertificate_sha256=" + nl::hex_encode(nl::sha256(certificate.payload)) +
            "\nhwid_sha256=" + std::string(hwid) +
            "\ndevice_public_key=" + nl::base64_encode(public_key) +
            "\npairing_code_sha256=" + nl::hex_encode(nl::sha256(std::span(
                reinterpret_cast<const std::uint8_t*>(pairing_code.data()), pairing_code.size()))) +
            "\nclient_nonce=" + std::string(client_nonce) +
            "\nclient_version=" + std::string(kClientVersion) + "\n";
    }

    session authenticate_loader(
        const nl::http_client& client,
        const personalization& certificate,
        const std::string_view hwid,
        const nl::device_key& device)
    {
        const nl::bytes public_key = device.public_key_sec1();
        std::string pairing_code = certificate.enrollment_secret;
        string_wipe_guard pairing_guard{&pairing_code};
        const challenge server_challenge = request_challenge(client, certificate.audience);
        const std::string client_nonce = nl::base64_encode(nl::random_bytes(24));
        const std::string proof_message = loader_auth_message(
            certificate, server_challenge, hwid, public_key, pairing_code, client_nonce);
        const nl::bytes proof = device.sign(std::span(
            reinterpret_cast<const std::uint8_t*>(proof_message.data()), proof_message.size()));

        std::string body =
            "{\"certificate_payload\":\"" + nl::base64_encode(certificate.payload) +
            "\",\"certificate_signature\":\"" + nl::base64_encode(certificate.signature) +
            "\",\"hwid_hash\":\"" + nl::json_escape(hwid) +
            "\",\"device_public_key\":\"" + nl::base64_encode(public_key) +
            "\",\"device_signature\":\"" + nl::base64_encode(proof) +
            "\",\"pairing_code\":\"" + nl::json_escape(pairing_code) +
            "\",\"client_nonce\":\"" + client_nonce +
            "\",\"client_version\":\"" + std::string(kClientVersion) +
            "\",\"server_challenge\":\"" + nl::json_escape(server_challenge.nonce) + "\"}";
        string_wipe_guard body_guard{&body};
        const nl::http_response response = client.post_json("/api/v1/loader/sessions", body, {}, 64 << 10);
        if (response.status == 428)
            throw std::runtime_error("Automatic device enrollment is unavailable. Download a fresh personal loader with /loader.");
        if (response.status == 403 && !pairing_code.empty())
            throw std::runtime_error("Device verification failed. If this PC changed, use /hwid-reset and download a fresh loader.");
        require_status(response, 201, "Loader authentication");
        return {nl::json_string(response.text(), "access_token")};
    }

    std::string artifact_ticket_message(
        const std::string_view audience,
        const challenge& server_challenge,
        const std::string_view platform,
        const nl::bytes& client_public_key,
        const std::string_view client_nonce)
    {
        return
            "nl-artifact-ticket-v1\naudience=" + std::string(audience) +
            "\nchallenge=" + server_challenge.nonce +
            "\nplatform=" + std::string(platform) +
            "\nclient_public_key=" + nl::base64_encode(client_public_key) +
            "\nclient_nonce=" + std::string(client_nonce) + "\n";
    }

    artifact_ticket request_artifact_ticket(
        const nl::http_client& client,
        const std::string_view audience,
        const std::string_view access_token,
        const nl::device_key& device,
        const nl::bytes& client_public_key)
    {
        constexpr std::string_view platform = "windows-x86";
        const challenge server_challenge = request_challenge(client, audience);
        const std::string client_nonce = nl::base64_encode(nl::random_bytes(24));
        const std::string proof_message = artifact_ticket_message(
            audience,
            server_challenge,
            platform,
            client_public_key,
            client_nonce);
        const nl::bytes proof = device.sign(std::span(
            reinterpret_cast<const std::uint8_t*>(proof_message.data()), proof_message.size()));
        const std::string body =
            "{\"platform\":\"" + std::string(platform) +
            "\",\"client_public_key\":\"" + nl::base64_encode(client_public_key) +
            "\",\"device_signature\":\"" + nl::base64_encode(proof) +
            "\",\"client_nonce\":\"" + client_nonce +
            "\",\"server_challenge\":\"" + nl::json_escape(server_challenge.nonce) + "\"}";
        const nl::http_response response = client.post_json(
            "/api/v1/artifacts/ticket",
            body,
            access_token,
            64 << 10);
        require_status(response, 201, "Artifact ticket");
        const std::string document = response.text();
        artifact_ticket result{
            nl::json_string(document, "ticket"),
            nl::json_string(document, "version"),
            nl::json_string(document, "sha256"),
            nl::json_integer(document, "size")};
        if (result.size <= 0 || result.size > static_cast<std::int64_t>(kMaximumArtifactBytes))
            throw std::runtime_error("Artifact ticket size is invalid");
        static_cast<void>(nl::hex_decode(result.sha256, 32));
        return result;
    }

    std::string security_event_message(
        const std::string_view audience,
        const challenge& server_challenge,
        const std::string_view event_id,
        const integrity_incident& incident,
        const std::string_view client_nonce)
    {
        return
            "nl-security-event-v1\naudience=" + std::string(audience) +
            "\nchallenge=" + server_challenge.nonce +
            "\nevent_id=" + std::string(event_id) +
            "\nevent_type=post_run_hash_mismatch" +
            "\ncomponent=" + incident.component +
            "\nexpected_sha256=" + incident.expected_sha256 +
            "\nobserved_sha256=" + incident.observed_sha256 +
            "\nclient_nonce=" + std::string(client_nonce) +
            "\nclient_version=" + std::string(kClientVersion) + "\n";
    }

    void report_security_event(
        const nl::http_client& client,
        const std::string_view audience,
        const std::string_view access_token,
        const nl::device_key& device,
        const integrity_incident& incident)
    {
        const challenge server_challenge = request_challenge(client, audience);
        const std::string event_id = nl::base64_encode(nl::random_bytes(24));
        const std::string client_nonce = nl::base64_encode(nl::random_bytes(24));
        const std::string message = security_event_message(
            audience, server_challenge, event_id, incident, client_nonce);
        const nl::bytes signature = device.sign(std::span(
            reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
        const std::string body =
            "{\"event_id\":\"" + nl::json_escape(event_id) +
            "\",\"event_type\":\"post_run_hash_mismatch" +
            "\",\"component\":\"" + nl::json_escape(incident.component) +
            "\",\"expected_sha256\":\"" + incident.expected_sha256 +
            "\",\"observed_sha256\":\"" + incident.observed_sha256 +
            "\",\"client_version\":\"" + std::string(kClientVersion) +
            "\",\"client_nonce\":\"" + nl::json_escape(client_nonce) +
            "\",\"server_challenge\":\"" + nl::json_escape(server_challenge.nonce) +
            "\",\"device_signature\":\"" + nl::base64_encode(signature) + "\"}";
        const nl::http_response response = client.post_json(
            "/api/v1/security/events", body, access_token, 64 << 10);
        require_status(response, 202, "Security incident report");
    }

    std::int64_t parse_header_integer(const std::string_view value, const std::string_view name)
    {
        std::int64_t result = 0;
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || result <= 0)
            throw std::runtime_error("Invalid artifact header: " + std::string(name));
        return result;
    }

    nl::bytes download_artifact(
        const nl::http_client& client,
        const std::string_view access_token,
        const artifact_ticket& ticket,
        const nl::ecdh_key& exchange,
        const nl::bytes& client_public_key)
    {
        const std::string body =
            "{\"ticket\":\"" + nl::json_escape(ticket.token) +
            "\",\"client_public_key\":\"" + nl::base64_encode(client_public_key) + "\"}";
        constexpr std::array<std::string_view, 7> headers{
            "X-NL-Server-Key",
            "X-NL-Nonce",
            "X-NL-Version",
            "X-NL-Platform",
            "X-NL-SHA256",
            "X-NL-Plaintext-Size",
            "X-NL-Signature"};
        const nl::http_response response = client.post_json(
            "/api/v1/artifacts/download",
            body,
            access_token,
            kMaximumArtifactBytes + 16,
            headers);
        require_status(response, 200, "Artifact download");

        const std::string version = response.header("X-NL-Version");
        const std::string platform = response.header("X-NL-Platform");
        const std::string sha = response.header("X-NL-SHA256");
        const std::int64_t plaintext_size = parse_header_integer(response.header("X-NL-Plaintext-Size"), "plaintext size");
        if (version != ticket.version || platform != "windows-x86" || sha != ticket.sha256 || plaintext_size != ticket.size)
            throw std::runtime_error("Artifact metadata changed after ticket issuance");
        const std::string manifest =
            "nl-artifact-v1\nversion=" + version +
            "\nplatform=" + platform +
            "\nsha256=" + sha +
            "\nsize=" + std::to_string(plaintext_size) + "\n";
        const nl::bytes artifact_signature = nl::base64_decode(response.header("X-NL-Signature"), 64, 64);
        if (!nl::verify_p256(
            nl::base64_decode(kServerPublicKey, 65, 65),
            std::span(reinterpret_cast<const std::uint8_t*>(manifest.data()), manifest.size()),
            artifact_signature))
            throw std::runtime_error("Artifact manifest signature is invalid");

        nl::bytes shared_secret = exchange.derive(nl::base64_decode(response.header("X-NL-Server-Key"), 65, 65));
        wipe_guard shared_guard{&shared_secret};
        nl::bytes salt_input(ticket.token.begin(), ticket.token.end());
        salt_input.insert(salt_input.end(), client_public_key.begin(), client_public_key.end());
        nl::bytes salt = nl::sha256(salt_input);
        wipe_guard salt_input_guard{&salt_input};
        constexpr std::string_view information = "nl-auth-artifact-envelope-v1";
        nl::bytes key = nl::hkdf_sha256(
            shared_secret,
            salt,
            std::span(reinterpret_cast<const std::uint8_t*>(information.data()), information.size()),
            32);
        wipe_guard key_guard{&key};
        nl::bytes plaintext = nl::aes_256_gcm_decrypt(
            key,
            nl::base64_decode(response.header("X-NL-Nonce"), 12, 12),
            response.body,
            std::span(reinterpret_cast<const std::uint8_t*>(manifest.data()), manifest.size()),
            static_cast<std::size_t>(plaintext_size));
        if (nl::hex_encode(nl::sha256(plaintext)) != sha)
        {
            nl::secure_clear(plaintext);
            throw std::runtime_error("Artifact plaintext integrity check failed");
        }
        return plaintext;
    }

    struct local_memory
    {
        HLOCAL value = nullptr;
        ~local_memory()
        {
            if (value)
                LocalFree(value);
        }
    };

    struct staging_directory
    {
        std::filesystem::path path;
        nl::win_handle lock;
    };

    staging_directory create_staging_directory()
    {
        std::wstring temporary(32768, L'\0');
        const DWORD length = GetTempPathW(static_cast<DWORD>(temporary.size()), temporary.data());
        if (length == 0 || length >= temporary.size())
            nl::throw_last_error("GetTempPathW");
        temporary.resize(length);

        PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                SDDL_REVISION_1,
                &raw_descriptor,
                nullptr))
            nl::throw_last_error("ConvertStringSecurityDescriptorToSecurityDescriptorW(staging)");
        local_memory descriptor{static_cast<HLOCAL>(raw_descriptor)};
        SECURITY_ATTRIBUTES security{};
        security.nLength = sizeof(security);
        security.lpSecurityDescriptor = raw_descriptor;
        security.bInheritHandle = FALSE;

        for (int attempt = 0; attempt < 16; ++attempt)
        {
            const std::filesystem::path directory =
                std::filesystem::path(temporary) / (L"nl-loader-" + nl::utf8_to_wide(nl::hex_encode(nl::random_bytes(12))));
            if (CreateDirectoryW(directory.c_str(), &security))
            {
                nl::win_handle directory_lock(CreateFileW(
                    directory.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr));
                if (!directory_lock)
                {
                    const DWORD error = GetLastError();
                    RemoveDirectoryW(directory.c_str());
                    nl::throw_last_error("CreateFileW(staging lock)", error);
                }
                FILE_ATTRIBUTE_TAG_INFO attributes{};
                if (!GetFileInformationByHandleEx(
                        directory_lock.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
                    (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                {
                    directory_lock.reset();
                    RemoveDirectoryW(directory.c_str());
                    throw std::runtime_error("Staging directory validation failed");
                }
                return staging_directory{directory, std::move(directory_lock)};
            }
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                nl::throw_last_error("CreateDirectoryW(staging)");
        }
        throw std::runtime_error("Unable to allocate a staging directory");
    }

    void write_staging_file(const std::filesystem::path& path, const std::span<const std::uint8_t> content)
    {
        nl::win_handle file(CreateFileW(
            path.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
            nullptr));
        if (!file)
            nl::throw_last_error("CreateFileW(staging write)");
        std::size_t offset = 0;
        while (offset < content.size())
        {
            const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(content.size() - offset, 1u << 20));
            DWORD written = 0;
            if (!WriteFile(file.get(), content.data() + offset, chunk, &written, nullptr) || written != chunk)
                nl::throw_last_error("WriteFile(staging)");
            offset += written;
        }
        if (!FlushFileBuffers(file.get()))
            nl::throw_last_error("FlushFileBuffers(staging)");
    }

    std::string hash_staging_handle(const HANDLE handle, const std::size_t maximum_bytes)
    {
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(handle, &size))
            nl::throw_last_error("GetFileSizeEx(staging)");
        if (size.QuadPart <= 0 || static_cast<unsigned long long>(size.QuadPart) > maximum_bytes)
            throw std::runtime_error("Staging file size is invalid");
        LARGE_INTEGER start{};
        if (!SetFilePointerEx(handle, start, nullptr, FILE_BEGIN))
            nl::throw_last_error("SetFilePointerEx(staging)");
        nl::bytes content(static_cast<std::size_t>(size.QuadPart));
        wipe_guard content_guard{&content};
        std::size_t offset = 0;
        while (offset < content.size())
        {
            const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(content.size() - offset, 1u << 20));
            DWORD read = 0;
            if (!ReadFile(handle, content.data() + offset, chunk, &read, nullptr) || read != chunk)
                nl::throw_last_error("ReadFile(staging)");
            offset += read;
        }
        return nl::hex_encode(nl::sha256(content));
    }

    nl::win_handle lock_and_verify_staging_file(
        const std::filesystem::path& path,
        const std::string_view expected_sha256,
        const std::size_t maximum_bytes)
    {
        nl::win_handle lock(CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr));
        if (!lock)
            nl::throw_last_error("CreateFileW(staging lock)");
        if (hash_staging_handle(lock.get(), maximum_bytes) != expected_sha256)
            throw std::runtime_error("Staging file integrity check failed");
        return lock;
    }

    void remove_or_schedule(const std::filesystem::path& path) noexcept
    {
        if (DeleteFileW(path.c_str()))
            return;
        MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }

    void remove_directory_or_schedule(const std::filesystem::path& path) noexcept
    {
        if (RemoveDirectoryW(path.c_str()))
            return;
        MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }

    injector_run_result run_injector(nl::bytes& artifact)
    {
        staging_directory staging = create_staging_directory();
        const std::filesystem::path injector_path = staging.path / L"injector.exe";
        const std::filesystem::path dll_path = staging.path / L"neverlose.dll";
        try
        {
            const std::string artifact_sha256 = nl::hex_encode(nl::sha256(artifact));
            nl::bytes injector = embedded_injector();
            wipe_guard injector_guard{&injector};
            write_staging_file(injector_path, injector);
            nl::secure_clear(injector);
            injector_guard.value = nullptr;
            write_staging_file(dll_path, artifact);
            nl::secure_clear(artifact);

            nl::win_handle injector_lock = lock_and_verify_staging_file(
                injector_path, kInjectorSHA256, 32ull << 20);
            nl::win_handle dll_lock = lock_and_verify_staging_file(
                dll_path, artifact_sha256, kMaximumArtifactBytes);

            std::wstring command = L"\"" + injector_path.wstring() + L"\"";
            std::vector<wchar_t> writable(command.begin(), command.end());
            writable.push_back(L'\0');
            STARTUPINFOW startup{};
            startup.cb = sizeof(startup);
            PROCESS_INFORMATION process{};
            if (!CreateProcessW(
                injector_path.c_str(),
                writable.data(),
                nullptr,
                nullptr,
                FALSE,
                0,
                nullptr,
                staging.path.c_str(),
                &startup,
                &process))
                nl::throw_last_error("CreateProcessW(injector)");
            nl::win_handle process_handle(process.hProcess);
            nl::win_handle thread_handle(process.hThread);
            if (WaitForSingleObject(process_handle.get(), INFINITE) != WAIT_OBJECT_0)
                nl::throw_last_error("WaitForSingleObject(injector)");
            DWORD exit_code = 1;
            if (!GetExitCodeProcess(process_handle.get(), &exit_code))
                nl::throw_last_error("GetExitCodeProcess(injector)");

            std::optional<integrity_incident> incident;
            try
            {
                const std::string observed_module = hash_staging_handle(dll_lock.get(), kMaximumArtifactBytes);
                if (observed_module != artifact_sha256)
                    incident = integrity_incident{"module", artifact_sha256, observed_module};
                const std::string observed_injector = hash_staging_handle(injector_lock.get(), 32ull << 20);
                if (!incident && observed_injector != kInjectorSHA256)
                    incident = integrity_incident{"injector", std::string(kInjectorSHA256), observed_injector};
            }
            catch (const std::exception& error)
            {
                std::fprintf(stderr, "[!] Post-run integrity check was inconclusive: %s\n", error.what());
            }
            dll_lock.reset();
            injector_lock.reset();
            remove_or_schedule(dll_path);
            remove_or_schedule(injector_path);
            staging.lock.reset();
            remove_directory_or_schedule(staging.path);
            return {static_cast<int>(exit_code), std::move(incident)};
        }
        catch (...)
        {
            nl::secure_clear(artifact);
            remove_or_schedule(dll_path);
            remove_or_schedule(injector_path);
            staging.lock.reset();
            remove_directory_or_schedule(staging.path);
            throw;
        }
    }

    void set_runtime_environment(const personalization& certificate)
    {
        SetEnvironmentVariableW(L"NL_HEARTBEAT_URL", nl::utf8_to_wide(certificate.audience).c_str());
        SetEnvironmentVariableW(L"NL_LOADER_ID", nl::utf8_to_wide(certificate.loader_id).c_str());
        if (!certificate.heartbeat_token.empty())
            SetEnvironmentVariableW(L"NL_HEARTBEAT_TOKEN", nl::utf8_to_wide(certificate.heartbeat_token).c_str());
    }

    void clear_runtime_environment()
    {
        SetEnvironmentVariableW(L"NL_HEARTBEAT_URL", nullptr);
        SetEnvironmentVariableW(L"NL_LOADER_ID", nullptr);
        SetEnvironmentVariableW(L"NL_HEARTBEAT_TOKEN", nullptr);
    }

    int self_test()
    {
        std::puts("[*] Running offline self-test...");
        const nl::bytes injector = embedded_injector();
        const std::string abc = "abc";
        if (nl::hex_encode(nl::sha256(std::span(
            reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size()))) !=
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            throw std::runtime_error("SHA-256 self-test failed");
        nl::ecdh_key first;
        nl::ecdh_key second;
        nl::bytes first_secret = first.derive(second.public_key_sec1());
        nl::bytes second_secret = second.derive(first.public_key_sec1());
        if (first_secret != second_secret)
            throw std::runtime_error("ECDH self-test failed");
        nl::secure_clear(first_secret);
        nl::secure_clear(second_secret);

        if (auto certificate = read_personalization())
        {
            string_wipe_guard enrollment_guard{&certificate->enrollment_secret};
            nl::win_handle loader_mutex = acquire_loader_mutex(certificate->loader_id);
            nl::device_key key = nl::device_key::load_or_create(certificate->loader_id);
            const std::string message = "device-key-self-test";
            const nl::bytes signature = key.sign(std::span(
                reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
            if (!nl::verify_p256(key.public_key_sec1(), std::span(
                reinterpret_cast<const std::uint8_t*>(message.data()), message.size()), signature))
                throw std::runtime_error("Device key self-test failed");
            std::puts("[+] Personalized certificate and device credential are valid.");
        }
        else
        {
            std::puts("[+] Generic template mode detected.");
        }
        std::printf("[+] Embedded injector verified (%zu bytes).\n", injector.size());
        std::puts("[+] Offline self-test passed. No game process was started.");
        return 0;
    }
}

int wmain(const int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleW(L"patchwin.cc loader");
    try
    {
        if (argc == 2 && std::wstring_view(argv[1]) == L"--self-test")
            return self_test();
        if (argc != 1)
        {
            std::puts("Usage: nl-loader.exe [--self-test]");
            return 2;
        }

        std::puts("patchwin.cc | secure loader");
        auto certificate = read_personalization();
        if (!certificate)
            throw std::runtime_error("This is a generic loader template. Download your personal loader through Discord.");
        string_wipe_guard enrollment_guard{&certificate->enrollment_secret};

        nl::win_handle loader_mutex = acquire_loader_mutex(certificate->loader_id);
        std::puts("[*] Verifying device...");
        nl::device_key device = nl::device_key::load_or_create(certificate->loader_id);
        const std::string hwid = hardware_hash();
        nl::http_client client(certificate->audience);
        const session authenticated = authenticate_loader(client, *certificate, hwid, device);
        secure_clear_string(certificate->enrollment_secret);

        std::puts("[*] Downloading signed module...");
        nl::ecdh_key exchange;
        const nl::bytes client_public_key = exchange.public_key_sec1();
        const artifact_ticket ticket = request_artifact_ticket(
            client,
            certificate->audience,
            authenticated.access_token,
            device,
            client_public_key);
        nl::bytes artifact = download_artifact(client, authenticated.access_token, ticket, exchange, client_public_key);
        wipe_guard artifact_guard{&artifact};
        std::printf("[+] Module %s verified.\n", ticket.version.c_str());

        set_runtime_environment(*certificate);
        const injector_run_result result = run_injector(artifact);
        clear_runtime_environment();
        artifact_guard.value = nullptr;
        if (result.incident)
        {
            std::fputs("[-] Protected module integrity changed while in use. Access has been suspended.\n", stderr);
            report_security_event(
                client,
                certificate->audience,
                authenticated.access_token,
                device,
                *result.incident);
            return 1;
        }
        if (result.exit_code != 0)
            std::printf("[-] Injector exited with code %d.\n", result.exit_code);
        return result.exit_code;
    }
    catch (const std::exception& error)
    {
        std::fprintf(stderr, "[-] %s\n", error.what());
        return 1;
    }
}
