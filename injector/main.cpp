#include <winsock2.h>
#include <Windows.h>
#include <bcrypt.h>
#include <psapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <TlHelp32.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "resource.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

namespace
{
    constexpr const char* kDllName = "neverlose.dll";
    constexpr const char* kPendingDllName =
        "neverlose.HideLegit.pending.dll";
    constexpr const char* kWindowClass = "Valve001";
    constexpr wchar_t kGameLaunchUri[] = L"steam://launch/730/option1";
    constexpr wchar_t kServerResourceType[] = L"BINARY";
    constexpr wchar_t kServerRuntimeDirectory[] = L"patchwin.cc";
    constexpr wchar_t kCloudDirectory[] = L"nl_cloud";
    constexpr unsigned short kServerWsPort = 30030;
    constexpr unsigned short kServerHttpPort = 30031;
    constexpr DWORD kServerStartupTimeoutMs = 15000;
    constexpr size_t kRuntimeRandomByteCount = 16;
    constexpr DWORD kServerVerifyBufferSize = 64 * 1024;
    constexpr DWORD kHeartbeatGraceLimit = 3;
    constexpr DWORD kWatchdogIntervalMs = 30000;
    constexpr DWORD kWatchdogTamperThreshold = 2;
    constexpr DWORD kWatchdogModuleWaitMs = 120000;
    constexpr DWORD kProcessAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

    class unique_handle
    {
    public:
        unique_handle() = default;
        explicit unique_handle(HANDLE value) : value_(value) {}

        unique_handle(const unique_handle&) = delete;
        unique_handle& operator=(const unique_handle&) = delete;

        unique_handle(unique_handle&& other) noexcept
            : value_(other.release())
        {
        }

        unique_handle& operator=(unique_handle&& other) noexcept
        {
            if (this != &other)
                reset(other.release());
            return *this;
        }

        ~unique_handle()
        {
            reset();
        }

        HANDLE get() const
        {
            return value_;
        }

        HANDLE release()
        {
            const HANDLE value = value_;
            value_ = INVALID_HANDLE_VALUE;
            return value;
        }

        void reset(HANDLE value = INVALID_HANDLE_VALUE)
        {
            if (value_ && value_ != INVALID_HANDLE_VALUE)
                CloseHandle(value_);
            value_ = value;
        }

        explicit operator bool() const
        {
            return value_ && value_ != INVALID_HANDLE_VALUE;
        }

    private:
        HANDLE value_ = INVALID_HANDLE_VALUE;
    };

    class local_memory
    {
    public:
        local_memory() = default;
        explicit local_memory(HLOCAL value) : value_(value) {}

        local_memory(const local_memory&) = delete;
        local_memory& operator=(const local_memory&) = delete;

        ~local_memory()
        {
            reset();
        }

        HLOCAL get() const
        {
            return value_;
        }

        void reset(HLOCAL value = nullptr)
        {
            if (value_)
                LocalFree(value_);
            value_ = value;
        }

    private:
        HLOCAL value_ = nullptr;
    };

    class winsock_session
    {
    public:
        winsock_session()
        {
            WSADATA data{};
            ready_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
        }

        ~winsock_session()
        {
            if (ready_)
                WSACleanup();
        }

        bool ready() const
        {
            return ready_;
        }

    private:
        bool ready_ = false;
    };

    void print_banner()
    {
        SetConsoleTitleA("patchwin.cc");
        std::puts("========================================");
        std::puts("              patchwin.cc");
        std::puts("========================================");
        std::puts("Tip: if it fails right after token entry, just launch it again.");
        std::puts("");
    }

    void print_status(const char* label, const char* message)
    {
        std::printf("%s %s\n", label, message);
    }

    // Smart App Control state: 0=Off, 1=Evaluation, 2=On. Only 1/2 block untrusted code.
    DWORD smart_app_control_state()
    {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", 0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
            return 0;
        DWORD value = 0;
        DWORD size = sizeof(value);
        DWORD type = 0;
        const LSTATUS status = RegQueryValueExW(key, L"VerifiedAndReputablePolicyState", nullptr, &type,
            reinterpret_cast<BYTE*>(&value), &size);
        RegCloseKey(key);
        if (status != ERROR_SUCCESS || type != REG_DWORD)
            return 0;
        return value;
    }

    void set_smart_app_control_off()
    {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", 0,
                KEY_SET_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
            return;
        DWORD value = 0;
        RegSetValueExW(key, L"VerifiedAndReputablePolicyState", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&value), sizeof(value));
        RegCloseKey(key);
    }

    // Memory integrity (HVCI/VBS) also blocks unsigned code even with SAC and
    // Defender off. Returns 1 when enforced.
    DWORD hvci_state()
    {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", 0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
            return 0;
        DWORD value = 0;
        DWORD size = sizeof(value);
        DWORD type = 0;
        const LSTATUS status = RegQueryValueExW(key, L"Enabled", nullptr, &type,
            reinterpret_cast<BYTE*>(&value), &size);
        RegCloseKey(key);
        if (status != ERROR_SUCCESS || type != REG_DWORD)
            return 0;
        return value;
    }

    void disable_hvci_vbs()
    {
        HKEY key = nullptr;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, nullptr, 0,
                KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, nullptr) == ERROR_SUCCESS)
        {
            DWORD value = 0;
            RegSetValueExW(key, L"EnableVirtualizationBasedSecurity", 0, REG_DWORD,
                reinterpret_cast<const BYTE*>(&value), sizeof(value));
            RegCloseKey(key);
        }
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", 0, nullptr, 0,
                KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, nullptr) == ERROR_SUCCESS)
        {
            DWORD value = 0;
            RegSetValueExW(key, L"Enabled", 0, REG_DWORD,
                reinterpret_cast<const BYTE*>(&value), sizeof(value));
            RegCloseKey(key);
        }
    }

    void run_hidden_command(const std::wstring& command)
    {
        SHELLEXECUTEINFOW info{};
        info.cbSize = sizeof(info);
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpFile = L"powershell.exe";
        info.lpParameters = command.c_str();
        info.nShow = SW_HIDE;
        if (!ShellExecuteExW(&info) || !info.hProcess)
            return;
        WaitForSingleObject(info.hProcess, 15000);
        CloseHandle(info.hProcess);
    }

    void add_defender_exclusions(const std::wstring& staging_dir)
    {
        std::wstring command =
            L"-NoProfile -ExecutionPolicy Bypass -Command \""
            L"Add-MpPreference -ExclusionPath '" + staging_dir + L"' -ErrorAction SilentlyContinue; "
            L"Add-MpPreference -ExclusionProcess 'csgo.exe' -ErrorAction SilentlyContinue\"";
        run_hidden_command(command);
    }

    // Consent-based repair for Windows code-integrity blocking. Only runs after the
    // user explicitly answers Y. Disables Smart App Control and adds Defender
    // exclusions for the staging folder and the game process.
    void offer_protection_fix(const std::wstring& staging_dir)
    {
        const DWORD sac_state = smart_app_control_state();
        const DWORD hvci = hvci_state();
        std::printf("[!] Windows code integrity is blocking the module.\n");
        std::printf("[!] Active blockers: %s%sDefender.\n",
            sac_state ? "Smart App Control, " : "",
            hvci ? "Memory Integrity (HVCI), " : "");
        std::printf("[?] Fix will add Defender exclusions%s%s and requires a REBOOT.\n",
            sac_state ? ", turn OFF Smart App Control" : "",
            hvci ? ", turn OFF Memory Integrity" : "");
        std::printf("[?] This lowers Windows protection on this PC. Apply? [Y/N]: ");

        const int answer = std::getchar();
        if (answer != 'Y' && answer != 'y')
        {
            print_status("[-]", "Fix skipped. Disable Smart App Control / Memory Integrity manually, then reboot and re-run.");
            return;
        }

        add_defender_exclusions(staging_dir);
        if (sac_state)
            set_smart_app_control_off();
        if (hvci)
            disable_hvci_vbs();

        print_status("[+]", "Fix applied (exclusions + code-integrity off).");
        print_status("[!]", "REBOOT this PC once, then re-run the loader.");
    }

    std::wstring parent_directory(const std::wstring& full_path)
    {
        const size_t separator = full_path.find_last_of(L"\\/");
        if (separator == std::wstring::npos)
            return {};

        return full_path.substr(0, separator);
    }

    std::wstring executable_directory()
    {
        std::vector<wchar_t> path(32768);
        const DWORD length = GetModuleFileNameW(
            nullptr,
            path.data(),
            static_cast<DWORD>(path.size())
        );

        if (!length || length >= path.size())
            return {};

        return parent_directory(std::wstring(path.data(), length));
    }

    bool resolve_dll_path(char (&full_path)[MAX_PATH])
    {
        char executable_path[MAX_PATH]{};
        const DWORD length = GetModuleFileNameA(
            nullptr,
            executable_path,
            MAX_PATH
        );
        if (!length || length >= MAX_PATH)
            return false;

        char* separator = std::strrchr(executable_path, '\\');
        if (!separator)
            return false;

        separator[1] = '\0';
        const std::string directory = executable_path;
        const std::string canonical_path = directory + kDllName;
        const std::string pending_path = directory + kPendingDllName;
        const DWORD pending_attributes =
            GetFileAttributesA(pending_path.c_str());

        const char* selected_path = canonical_path.c_str();
        if (pending_attributes != INVALID_FILE_ATTRIBUTES &&
            !(pending_attributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            if (CopyFileA(
                    pending_path.c_str(),
                    canonical_path.c_str(),
                    FALSE))
            {
                print_status("[+]", "Pending DLL deployed; backup kept.");
            }
            else
            {
                print_status(
                    "[-]",
                    "Current DLL is busy; close CS:GO and launch again."
                );
                return false;
            }
        }

        const DWORD selected_attributes =
            GetFileAttributesA(selected_path);
        if (selected_attributes == INVALID_FILE_ATTRIBUTES ||
            (selected_attributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            return false;
        }

        return strcpy_s(full_path, MAX_PATH, selected_path) == 0;
    }

    std::wstring process_executable_directory(DWORD process_id)
    {
        HANDLE process = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            process_id
        );
        if (!process)
            return {};

        std::vector<wchar_t> path(32768);
        DWORD length = static_cast<DWORD>(path.size());
        const BOOL resolved = QueryFullProcessImageNameW(
            process,
            0,
            path.data(),
            &length
        );
        CloseHandle(process);

        if (!resolved || !length)
            return {};

        return parent_directory(std::wstring(path.data(), length));
    }

    bool ensure_directory_exists(const std::wstring& directory)
    {
        if (CreateDirectoryW(directory.c_str(), nullptr))
            return true;

        if (GetLastError() != ERROR_ALREADY_EXISTS)
            return false;

        const DWORD attributes = GetFileAttributesW(directory.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_DIRECTORY);
    }

    bool prepare_game_cloud_storage(
        DWORD process_id,
        std::wstring& cloud_path)
    {
        const std::wstring game_directory =
            process_executable_directory(process_id);
        if (game_directory.empty())
        {
            print_status("[-]", "Failed to resolve the game directory.");
            return false;
        }

        cloud_path = game_directory + L"\\" + kCloudDirectory;
        if (!ensure_directory_exists(cloud_path))
        {
            std::wprintf(
                L"[-] Failed to create game storage directory: %ls (error %lu).\n",
                cloud_path.c_str(),
                GetLastError()
            );
            return false;
        }

        std::wprintf(L"[+] Game storage path: %ls\n", cloud_path.c_str());
        return true;
    }

    bool loopback_port_open(unsigned short port)
    {
        SOCKET socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket_handle == INVALID_SOCKET)
            return false;

        u_long non_blocking = 1;
        if (ioctlsocket(socket_handle, FIONBIO, &non_blocking) == SOCKET_ERROR)
        {
            closesocket(socket_handle);
            return false;
        }

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        const int connect_result = connect(
            socket_handle,
            reinterpret_cast<const sockaddr*>(&address),
            sizeof(address)
        );

        if (connect_result == 0)
        {
            closesocket(socket_handle);
            return true;
        }

        const int connect_error = WSAGetLastError();
        if (connect_error != WSAEWOULDBLOCK &&
            connect_error != WSAEINPROGRESS &&
            connect_error != WSAEINVAL)
        {
            closesocket(socket_handle);
            return false;
        }

        fd_set write_set;
        FD_ZERO(&write_set);
        FD_SET(socket_handle, &write_set);

        fd_set error_set;
        FD_ZERO(&error_set);
        FD_SET(socket_handle, &error_set);

        timeval timeout{};
        timeout.tv_usec = 200000;

        const int selected = select(0, nullptr, &write_set, &error_set, &timeout);
        if (selected <= 0)
        {
            closesocket(socket_handle);
            return false;
        }

        int socket_error = 0;
        int socket_error_size = sizeof(socket_error);
        const bool connected =
            getsockopt(
                socket_handle,
                SOL_SOCKET,
                SO_ERROR,
                reinterpret_cast<char*>(&socket_error),
                &socket_error_size
            ) == 0 &&
            socket_error == 0;

        closesocket(socket_handle);
        return connected;
    }

    bool server_ports_ready()
    {
        return loopback_port_open(kServerWsPort) &&
            loopback_port_open(kServerHttpPort);
    }

    bool write_all(HANDLE file, const BYTE* data, DWORD size)
    {
        DWORD offset = 0;
        while (offset < size)
        {
            DWORD written = 0;
            if (!WriteFile(file, data + offset, size - offset, &written, nullptr) ||
                written == 0)
            {
                return false;
            }
            offset += written;
        }
        return FlushFileBuffers(file) != FALSE;
    }

    bool query_token_information(
        HANDLE token,
        TOKEN_INFORMATION_CLASS information_class,
        std::vector<BYTE>& buffer)
    {
        DWORD required_size = 0;
        GetTokenInformation(
            token,
            information_class,
            nullptr,
            0,
            &required_size);
        if (!required_size || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            return false;

        buffer.resize(required_size);
        return GetTokenInformation(
            token,
            information_class,
            buffer.data(),
            required_size,
            &required_size) != FALSE;
    }

    const wchar_t* integrity_sddl_alias(DWORD integrity_rid)
    {
        if (integrity_rid >= SECURITY_MANDATORY_SYSTEM_RID)
            return L"SI";
        if (integrity_rid >= SECURITY_MANDATORY_HIGH_RID)
            return L"HI";
        if (integrity_rid >= SECURITY_MANDATORY_MEDIUM_RID)
            return L"ME";
        if (integrity_rid >= SECURITY_MANDATORY_LOW_RID)
            return L"LW";
        return L"UN";
    }

    bool build_runtime_security(
        SECURITY_ATTRIBUTES& attributes,
        local_memory& descriptor)
    {
        HANDLE raw_token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token))
            return false;
        unique_handle token(raw_token);

        std::vector<BYTE> user_buffer;
        std::vector<BYTE> integrity_buffer;
        if (!query_token_information(token.get(), TokenUser, user_buffer) ||
            !query_token_information(
                token.get(), TokenIntegrityLevel, integrity_buffer))
        {
            return false;
        }

        const auto* token_user =
            reinterpret_cast<const TOKEN_USER*>(user_buffer.data());
        const auto* token_integrity =
            reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(
                integrity_buffer.data());
        if (!IsValidSid(token_user->User.Sid) ||
            !IsValidSid(token_integrity->Label.Sid))
        {
            return false;
        }

        const UCHAR sub_authority_count =
            *GetSidSubAuthorityCount(token_integrity->Label.Sid);
        if (!sub_authority_count)
            return false;

        const DWORD integrity_rid = *GetSidSubAuthority(
            token_integrity->Label.Sid,
            sub_authority_count - 1);

        LPWSTR raw_user_sid = nullptr;
        if (!ConvertSidToStringSidW(token_user->User.Sid, &raw_user_sid))
            return false;
        local_memory user_sid(raw_user_sid);

        const std::wstring sid = raw_user_sid;
        const std::wstring sddl =
            L"O:" + sid +
            L"G:" + sid +
            L"D:P(A;;FA;;;SY)(A;;FA;;;" + sid + L")" +
            L"S:(ML;;NW;;;" + integrity_sddl_alias(integrity_rid) + L")";

        PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.c_str(),
                SDDL_REVISION_1,
                &raw_descriptor,
                nullptr))
        {
            return false;
        }

        descriptor.reset(static_cast<HLOCAL>(raw_descriptor));
        attributes = {};
        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = raw_descriptor;
        attributes.bInheritHandle = FALSE;
        return true;
    }

    bool random_hex(std::wstring& value)
    {
        std::array<UCHAR, kRuntimeRandomByteCount> random_bytes{};
        const NTSTATUS status = BCryptGenRandom(
            nullptr,
            random_bytes.data(),
            static_cast<ULONG>(random_bytes.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status))
            return false;

        static constexpr wchar_t digits[] = L"0123456789abcdef";
        value.clear();
        value.reserve(random_bytes.size() * 2);
        for (const UCHAR byte : random_bytes)
        {
            value.push_back(digits[byte >> 4]);
            value.push_back(digits[byte & 0x0F]);
        }
        return true;
    }

    bool temporary_directory(std::wstring& directory)
    {
        std::vector<wchar_t> buffer(32768);
        const DWORD length = GetTempPathW(
            static_cast<DWORD>(buffer.size()),
            buffer.data());
        if (!length || length >= buffer.size())
            return false;

        directory.assign(buffer.data(), length);
        if (!directory.empty() && directory.back() != L'\\')
            directory.push_back(L'\\');
        return true;
    }

    bool create_secure_runtime_directory(
        SECURITY_ATTRIBUTES& security,
        std::wstring& runtime_directory,
        unique_handle& directory_handle)
    {
        std::wstring temp_directory;
        if (!temporary_directory(temp_directory))
            return false;

        for (int attempt = 0; attempt < 16; ++attempt)
        {
            std::wstring nonce;
            if (!random_hex(nonce))
                return false;

            runtime_directory =
                temp_directory + kServerRuntimeDirectory + L"-runtime-" + nonce;
            if (!CreateDirectoryW(runtime_directory.c_str(), &security))
            {
                if (GetLastError() == ERROR_ALREADY_EXISTS)
                    continue;
                return false;
            }

            directory_handle.reset(CreateFileW(
                runtime_directory.c_str(),
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr));
            if (!directory_handle)
            {
                RemoveDirectoryW(runtime_directory.c_str());
                return false;
            }

            FILE_ATTRIBUTE_TAG_INFO tag_info{};
            if (!GetFileInformationByHandleEx(
                    directory_handle.get(),
                    FileAttributeTagInfo,
                    &tag_info,
                    sizeof(tag_info)) ||
                (tag_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            {
                directory_handle.reset();
                RemoveDirectoryW(runtime_directory.c_str());
                return false;
            }

            return true;
        }

        SetLastError(ERROR_ALREADY_EXISTS);
        return false;
    }

    bool verify_file_contents(
        HANDLE file,
        const BYTE* expected,
        DWORD expected_size)
    {
        LARGE_INTEGER file_size{};
        if (!GetFileSizeEx(file, &file_size) ||
            file_size.QuadPart != expected_size)
        {
            return false;
        }

        LARGE_INTEGER start{};
        if (!SetFilePointerEx(file, start, nullptr, FILE_BEGIN))
            return false;

        std::vector<BYTE> buffer(kServerVerifyBufferSize);
        DWORD offset = 0;
        while (offset < expected_size)
        {
            const DWORD remaining = expected_size - offset;
            const DWORD requested =
                remaining < buffer.size()
                ? remaining
                : static_cast<DWORD>(buffer.size());

            DWORD bytes_read = 0;
            if (!ReadFile(
                    file,
                    buffer.data(),
                    requested,
                    &bytes_read,
                    nullptr) ||
                bytes_read != requested ||
                std::memcmp(
                    buffer.data(),
                    expected + offset,
                    requested) != 0)
            {
                return false;
            }
            offset += bytes_read;
        }

        return true;
    }

    void remove_runtime_artifacts(
        const std::wstring& server_path,
        const std::wstring& runtime_directory,
        unique_handle& directory_handle)
    {
        DeleteFileW(server_path.c_str());
        directory_handle.reset();
        RemoveDirectoryW(runtime_directory.c_str());
    }

    void schedule_runtime_cleanup(
        const std::wstring& server_path,
        const std::wstring& runtime_directory)
    {
        if (!DeleteFileW(server_path.c_str()))
        {
            MoveFileExW(
                server_path.c_str(),
                nullptr,
                MOVEFILE_DELAY_UNTIL_REBOOT);
        }

        if (!RemoveDirectoryW(runtime_directory.c_str()))
        {
            MoveFileExW(
                runtime_directory.c_str(),
                nullptr,
                MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }

    bool extract_embedded_server(
        std::wstring& server_path,
        std::wstring& runtime_directory,
        unique_handle& directory_handle)
    {
        HMODULE self = GetModuleHandleW(nullptr);
        HRSRC resource = FindResourceW(
            self,
            MAKEINTRESOURCEW(IDR_NEVERLOSE_SERVER),
            kServerResourceType
        );
        if (!resource)
        {
            std::printf("[-] Embedded server resource was not found (error %lu).\n", GetLastError());
            return false;
        }

        const DWORD resource_size = SizeofResource(self, resource);
        HGLOBAL loaded_resource = LoadResource(self, resource);
        if (!resource_size || !loaded_resource)
        {
            std::printf("[-] Embedded server resource is invalid (error %lu).\n", GetLastError());
            return false;
        }

        const BYTE* resource_data =
            static_cast<const BYTE*>(LockResource(loaded_resource));
        if (!resource_data)
        {
            std::printf("[-] Embedded server resource could not be locked (error %lu).\n", GetLastError());
            return false;
        }

        SECURITY_ATTRIBUTES security{};
        local_memory security_descriptor;
        if (!build_runtime_security(security, security_descriptor))
        {
            std::printf(
                "[-] Failed to build runtime security descriptor (error %lu).\n",
                GetLastError());
            return false;
        }

        if (!create_secure_runtime_directory(
                security,
                runtime_directory,
                directory_handle))
        {
            std::printf(
                "[-] Failed to create secure server runtime directory (error %lu).\n",
                GetLastError());
            return false;
        }

        std::wstring file_nonce;
        if (!random_hex(file_nonce))
        {
            remove_runtime_artifacts(
                server_path, runtime_directory, directory_handle);
            return false;
        }
        server_path =
            runtime_directory + L"\\patchwin-server-" + file_nonce + L".exe";

        unique_handle file(CreateFileW(
            server_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            &security,
            CREATE_NEW,
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY,
            nullptr
        ));
        if (!file)
        {
            std::printf("[-] Failed to create embedded server file (error %lu).\n", GetLastError());
            remove_runtime_artifacts(
                server_path, runtime_directory, directory_handle);
            return false;
        }

        if (!write_all(file.get(), resource_data, resource_size) ||
            !verify_file_contents(
                file.get(), resource_data, resource_size))
        {
            std::printf(
                "[-] Embedded server verification failed (error %lu).\n",
                GetLastError());
            file.reset();
            remove_runtime_artifacts(
                server_path, runtime_directory, directory_handle);
            return false;
        }

        file.reset();
        return true;
    }

    bool launch_embedded_server(
        const std::wstring& server_path,
        const std::wstring& working_directory,
        const std::wstring& cloud_path,
        PROCESS_INFORMATION& process_info)
    {
        SetLastError(ERROR_SUCCESS);
        const DWORD old_value_size =
            GetEnvironmentVariableW(L"NL_CLOUD_PATH", nullptr, 0);
        const bool had_old_value =
            old_value_size > 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND;

        std::wstring old_value;
        if (old_value_size > 0)
        {
            old_value.resize(old_value_size);
            const DWORD copied = GetEnvironmentVariableW(
                L"NL_CLOUD_PATH",
                old_value.data(),
                old_value_size
            );
            old_value.resize(copied);
        }

        if (!SetEnvironmentVariableW(L"NL_CLOUD_PATH", cloud_path.c_str()))
        {
            std::printf("[-] Failed to configure server storage path (error %lu).\n", GetLastError());
            return false;
        }

        std::wstring command_line = L"\"" + server_path + L"\"";
        std::vector<wchar_t> writable_command(
            command_line.begin(),
            command_line.end()
        );
        writable_command.push_back(L'\0');

        STARTUPINFOW startup_info{};
        startup_info.cb = sizeof(startup_info);
        process_info = {};

        const BOOL launched = CreateProcessW(
            server_path.c_str(),
            writable_command.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            working_directory.c_str(),
            &startup_info,
            &process_info
        );
        const DWORD launch_error = launched ? ERROR_SUCCESS : GetLastError();

        if (had_old_value)
            SetEnvironmentVariableW(L"NL_CLOUD_PATH", old_value.c_str());
        else
            SetEnvironmentVariableW(L"NL_CLOUD_PATH", nullptr);

        if (!launched)
        {
            std::printf("[-] Failed to launch embedded server (error %lu).\n", launch_error);
            return false;
        }

        return true;
    }

    bool wait_for_server(HANDLE process)
    {
        const ULONGLONG started = GetTickCount64();
        while (GetTickCount64() - started < kServerStartupTimeoutMs)
        {
            if (server_ports_ready())
                return true;

            if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0)
            {
                DWORD exit_code = 0;
                GetExitCodeProcess(process, &exit_code);
                std::printf("[-] Embedded server exited during startup (code %lu).\n", exit_code);
                return false;
            }

            Sleep(100);
        }

        print_status("[-]", "Embedded server startup timed out.");
        return false;
    }

    bool ensure_server(const std::wstring& cloud_path)
    {
        const bool ws_open = loopback_port_open(kServerWsPort);
        const bool http_open = loopback_port_open(kServerHttpPort);

        if (ws_open && http_open)
        {
            print_status("[+]", "patchwin.cc server is already running.");
            return true;
        }

        if (ws_open || http_open)
        {
            print_status("[-]", "Only one patchwin.cc server port is available; check ports 30030/30031.");
            return false;
        }

        const std::wstring working_directory = executable_directory();
        if (working_directory.empty())
        {
            print_status("[-]", "Failed to resolve injector directory.");
            return false;
        }

        std::wstring server_path;
        std::wstring runtime_directory;
        unique_handle directory_handle;
        if (!extract_embedded_server(
                server_path,
                runtime_directory,
                directory_handle))
            return false;

        PROCESS_INFORMATION process_info{};
        if (!launch_embedded_server(
            server_path,
            working_directory,
            cloud_path,
            process_info))
        {
            remove_runtime_artifacts(
                server_path,
                runtime_directory,
                directory_handle);
            return false;
        }
        if (!process_info.hProcess || !process_info.hThread)
        {
            if (process_info.hProcess)
            {
                TerminateProcess(process_info.hProcess, 1);
                WaitForSingleObject(process_info.hProcess, 5000);
                CloseHandle(process_info.hProcess);
            }
            if (process_info.hThread)
                CloseHandle(process_info.hThread);

            remove_runtime_artifacts(
                server_path,
                runtime_directory,
                directory_handle);
            SetLastError(ERROR_INVALID_HANDLE);
            return false;
        }

        unique_handle process(process_info.hProcess);
        unique_handle thread(process_info.hThread);
        const DWORD process_id = process_info.dwProcessId;
        directory_handle.reset();

        thread.reset();
        std::printf("[+] Embedded server started (PID: %lu).\n", process_id);

        const bool ready = wait_for_server(process.get());
        if (!ready && WaitForSingleObject(process.get(), 0) != WAIT_OBJECT_0)
        {
            TerminateProcess(process.get(), 1);
            WaitForSingleObject(process.get(), 5000);
        }

        if (!ready)
        {
            remove_runtime_artifacts(
                server_path,
                runtime_directory,
                directory_handle);
            return false;
        }

        schedule_runtime_cleanup(server_path, runtime_directory);
        print_status("[+]", "patchwin.cc server is ready.");
        return true;
    }


    LPVOID GetModBase(DWORD pid, const wchar_t* name)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return nullptr;

        MODULEENTRY32W me = { sizeof(me) };
        LPVOID base = nullptr;
        for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me))
        {
            if (!_wcsicmp(me.szModule, name))
            {
                base = me.modBaseAddr;
                break;
            }
        }
        CloseHandle(snap);
        return base;
    }

    void RestoreNtOpenFile(HANDLE hProcess)
    {
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (!hNtdll)
                return;

            LPVOID pLocal = GetProcAddress(hNtdll, "NtOpenFile");
            if (!pLocal)
                return;

            DWORD pid = GetProcessId(hProcess);
            LPVOID pRemote = GetModBase(pid, L"ntdll.dll");
            if (!pRemote)
                return;

            LPVOID target = (LPVOID)((uintptr_t)pRemote + ((uintptr_t)pLocal - (uintptr_t)hNtdll));

            char orig[5]{};

            wchar_t path[MAX_PATH]{};
            const UINT system_length = GetSystemDirectoryW(path, MAX_PATH);
            if (!system_length || system_length >= MAX_PATH)
                return;
            if (wcscat_s(path, L"\\ntdll.dll") != 0)
                return;

            HMODULE hFresh = LoadLibraryExW(path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
            if (!hFresh)
                return;

            LPVOID pFn = GetProcAddress(hFresh, "NtOpenFile");
            if (pFn)
                memcpy(orig, pFn, sizeof(orig));
            FreeLibrary(hFresh);

            if (!pFn)
                return;

            DWORD oldProt = 0;
            if (VirtualProtectEx(hProcess, target, sizeof(orig), PAGE_EXECUTE_READWRITE, &oldProt))
            {
                SIZE_T bytes_written = 0;
                const BOOL written = WriteProcessMemory(
                    hProcess,
                    target,
                    orig,
                    sizeof(orig),
                    &bytes_written);
                DWORD ignored = 0;
                VirtualProtectEx(
                    hProcess,
                    target,
                    sizeof(orig),
                    oldProt,
                    &ignored);
                if (written && bytes_written == sizeof(orig))
                    FlushInstructionCache(hProcess, target, sizeof(orig));
            }
    }


    bool launch_game_if_needed()
    {
        if (FindWindowA(kWindowClass, nullptr))
            return true;

        print_status("[*]", "CS:GO is not running. Launching it through Steam...");

        const HINSTANCE result = ShellExecuteW(
            nullptr,
            L"open",
            kGameLaunchUri,
            nullptr,
            nullptr,
            SW_SHOWNORMAL
        );

        const INT_PTR result_code = reinterpret_cast<INT_PTR>(result);
        if (result_code <= 32)
        {
            std::printf("[-] Failed to launch CS:GO through Steam (ShellExecute code: %lld).\n",
                static_cast<long long>(result_code));
            return false;
        }

        print_status("[+]", "Steam launch request sent.");
        return true;
    }

    HWND wait_for_game_window(DWORD& process_id)
    {
        print_status("[*]", "Waiting for CS:GO...");

        HWND window = nullptr;
        while (!window)
        {
            window = FindWindowA(kWindowClass, nullptr);
            if (!window)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            GetWindowThreadProcessId(window, &process_id);
        }

        return window;
    }

    std::wstring read_env(const wchar_t* name)
    {
        const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
        if (!size)
            return {};
        std::wstring value(size, L'\0');
        const DWORD copied = GetEnvironmentVariableW(name, value.data(), size);
        value.resize(copied);
        return value;
    }

    bool token_is_plain(const std::wstring& value)
    {
        if (value.empty() || value.size() > 256)
            return false;
        for (const wchar_t character : value)
        {
            const bool ok = (character >= L'a' && character <= L'z') ||
                (character >= L'A' && character <= L'Z') ||
                (character >= L'0' && character <= L'9') ||
                character == L'-' || character == L'_';
            if (!ok)
                return false;
        }
        return true;
    }

    constexpr wchar_t kHeartbeatStateKey[] = L"SOFTWARE\\patchwin.cc\\loader\\Runtime";
    constexpr wchar_t kHeartbeatStateValue[] = L"CheckFailures";

    DWORD heartbeat_failure_count()
    {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kHeartbeatStateKey, 0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
            return 0;

        DWORD value = 0;
        DWORD size = sizeof(value);
        DWORD type = 0;
        const LSTATUS status = RegQueryValueExW(
            key, kHeartbeatStateValue, nullptr, &type,
            reinterpret_cast<BYTE*>(&value), &size);
        RegCloseKey(key);
        if (status != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(value))
            return 0;
        return value;
    }

    void store_heartbeat_failure_count(const DWORD count)
    {
        HKEY key = nullptr;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kHeartbeatStateKey, 0, nullptr,
                REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_WOW64_64KEY,
                nullptr, &key, nullptr) != ERROR_SUCCESS)
            return;

        RegSetValueExW(key, kHeartbeatStateValue, 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&count), sizeof(count));
        RegCloseKey(key);
    }

    bool heartbeat_unreachable_continue(const char* reason)
    {
        const DWORD failures = heartbeat_failure_count();
        if (failures + 1 > kHeartbeatGraceLimit)
        {
            print_status("[-]", "License could not be verified for several runs in a row. Connect to the internet and try again.");
            return false;
        }
        store_heartbeat_failure_count(failures + 1);
        std::printf("[!] %s Offline grace %lu/%lu used.\n", reason, failures + 1, kHeartbeatGraceLimit);
        return true;
    }

    // Verifies the personal license against the auth site. An explicit
    // "license inactive" answer blocks the launch immediately. Unreachable
    // server is tolerated only for a small number of consecutive runs
    // (grace counter in the registry), after which the launch is blocked too,
    // so blocking the auth endpoint no longer bypasses the check.
    bool verify_license_heartbeat()
    {
        const std::wstring url = read_env(L"NL_HEARTBEAT_URL");
        const std::wstring loader_id = read_env(L"NL_LOADER_ID");
        const std::wstring heartbeat_token = read_env(L"NL_HEARTBEAT_TOKEN");
        if (url.empty() || loader_id.empty() || heartbeat_token.empty())
        {
            print_status("[*]", "No runtime license binding present; continuing.");
            return true;
        }
        if (!token_is_plain(loader_id) || !token_is_plain(heartbeat_token))
        {
            print_status("[-]", "Runtime license binding is malformed.");
            return false;
        }

        std::string body;
        body += "{\"loader_id\":\"";
        for (const wchar_t character : loader_id)
            body.push_back(static_cast<char>(character));
        body += "\",\"heartbeat_token\":\"";
        for (const wchar_t character : heartbeat_token)
            body.push_back(static_cast<char>(character));
        body += "\"}";

        URL_COMPONENTS components{};
        components.dwStructSize = sizeof(components);
        components.dwHostNameLength = static_cast<DWORD>(-1);
        components.dwUrlPathLength = static_cast<DWORD>(-1);
        components.dwExtraInfoLength = static_cast<DWORD>(-1);
        if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &components) ||
            components.nScheme != INTERNET_SCHEME_HTTPS || !components.dwHostNameLength)
        {
            print_status("[-]", "Runtime license endpoint is invalid.");
            return false;
        }

        HINTERNET session_handle = WinHttpOpen(
            L"patchwin.cc runtime/1.0",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!session_handle)
            return heartbeat_unreachable_continue("License check could not start.");

        DWORD secure_protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(
            session_handle,
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            &secure_protocols,
            sizeof(secure_protocols));
        WinHttpSetTimeouts(session_handle, 8000, 10000, 10000, 20000);

        const std::wstring host(components.lpszHostName, components.dwHostNameLength);
        HINTERNET connection = WinHttpConnect(session_handle, host.c_str(), components.nPort, 0);
        HINTERNET request = nullptr;
        if (connection)
        {
            request = WinHttpOpenRequest(
                connection,
                L"POST",
                L"/api/v1/loader/heartbeat",
                nullptr,
                WINHTTP_NO_REFERER,
                nullptr,
                WINHTTP_FLAG_SECURE);
        }
        if (!request)
        {
            if (connection)
                WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session_handle);
            return heartbeat_unreachable_continue("License check could not connect.");
        }

        DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy));

        const wchar_t headers[] =
            L"Content-Type: application/json; charset=utf-8\r\n"
            L"Accept: application/json\r\n";
        const BOOL sent = WinHttpSendRequest(
            request,
            headers,
            static_cast<DWORD>(std::wcslen(headers)),
            const_cast<char*>(body.data()),
            static_cast<DWORD>(body.size()),
            static_cast<DWORD>(body.size()),
            0);

        bool reached_server = false;
        bool license_inactive = false;
        if (!sent || !WinHttpReceiveResponse(request, nullptr))
        {
            print_status("[!]", "License check did not reach the server.");
        }
        else
        {
            reached_server = true;
            DWORD status = 0;
            DWORD status_size = sizeof(status);
            WinHttpQueryHeaders(
                request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &status,
                &status_size,
                WINHTTP_NO_HEADER_INDEX);
            if (status == 200)
            {
                print_status("[+]", "Runtime license verified.");
            }
            else if (status == 403 || status == 401)
            {
                print_status("[-]", "License is not active. Contact support in Discord.");
                license_inactive = true;
            }
            else
            {
                std::printf("[!] License check returned HTTP %lu.\n", status);
            }
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session_handle);

        if (license_inactive)
            return false;
        if (reached_server)
        {
            store_heartbeat_failure_count(0);
            return true;
        }
        return heartbeat_unreachable_continue("License check did not reach the server.");
    }

    typedef LONG (NTAPI* NtQueryInformationProcessFn)(
        HANDLE process, DWORD info_class, PVOID info, ULONG size, PULONG returned);

    ULONG peb_nt_global_flags()
    {
        ULONG flags = 0;
        __asm
        {
            mov eax, dword ptr fs:[48]
            mov ecx, dword ptr [eax + 104]
            mov flags, ecx
        }
        return flags & 0x70u;
    }

    bool debug_port_present()
    {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            return false;
        const auto query = reinterpret_cast<NtQueryInformationProcessFn>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (!query)
            return false;

        DWORD_PTR port = 0;
        if (query(GetCurrentProcess(), 7, &port, sizeof(port), nullptr) == 0 && port != 0)
            return true;

        HANDLE debug_object = nullptr;
        if (query(GetCurrentProcess(), 0x1E, &debug_object, sizeof(debug_object), nullptr) == 0 &&
            debug_object != nullptr)
        {
            CloseHandle(debug_object);
            return true;
        }
        return false;
    }

    bool debugger_detected()
    {
        if (IsDebuggerPresent())
            return true;

        BOOL remote_present = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_present) && remote_present)
            return true;

        if (peb_nt_global_flags() != 0)
            return true;

        return debug_port_present();
    }

    // Wipes the DOS/NT headers of the running image so a live memory dump no
    // longer parses as a PE. Called only after the embedded server resource has
    // been extracted, so the headers are no longer needed.
    void erase_own_pe_header()
    {
        const HMODULE self = GetModuleHandleW(nullptr);
        if (!self)
            return;

        const SIZE_T header_size = 0x400;
        DWORD old_protection = 0;
        if (!VirtualProtect(self, header_size, PAGE_READWRITE, &old_protection))
            return;

        SecureZeroMemory(self, header_size);

        DWORD restored = 0;
        VirtualProtect(self, header_size, old_protection, &restored);
    }

    enum class heartbeat_state
    {
        active,
        inactive,
        unreachable
    };

    // Lightweight heartbeat used by the resident watchdog. Unlike the startup
    // check it never touches the offline grace counter.
    heartbeat_state query_heartbeat(
        const std::wstring& url,
        const std::wstring& loader_id,
        const std::wstring& heartbeat_token)
    {
        std::string body;
        body += "{\"loader_id\":\"";
        for (const wchar_t character : loader_id)
            body.push_back(static_cast<char>(character));
        body += "\",\"heartbeat_token\":\"";
        for (const wchar_t character : heartbeat_token)
            body.push_back(static_cast<char>(character));
        body += "\"}";

        URL_COMPONENTS components{};
        components.dwStructSize = sizeof(components);
        components.dwHostNameLength = static_cast<DWORD>(-1);
        components.dwUrlPathLength = static_cast<DWORD>(-1);
        components.dwExtraInfoLength = static_cast<DWORD>(-1);
        if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &components) ||
            components.nScheme != INTERNET_SCHEME_HTTPS || !components.dwHostNameLength)
            return heartbeat_state::unreachable;

        HINTERNET session_handle = WinHttpOpen(
            L"patchwin.cc watchdog/1.0",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!session_handle)
            return heartbeat_state::unreachable;

        DWORD secure_protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(session_handle, WINHTTP_OPTION_SECURE_PROTOCOLS, &secure_protocols, sizeof(secure_protocols));
        WinHttpSetTimeouts(session_handle, 8000, 10000, 10000, 20000);

        heartbeat_state result = heartbeat_state::unreachable;
        const std::wstring host(components.lpszHostName, components.dwHostNameLength);
        HINTERNET connection = WinHttpConnect(session_handle, host.c_str(), components.nPort, 0);
        HINTERNET request = nullptr;
        if (connection)
        {
            request = WinHttpOpenRequest(
                connection,
                L"POST",
                L"/api/v1/loader/heartbeat",
                nullptr,
                WINHTTP_NO_REFERER,
                nullptr,
                WINHTTP_FLAG_SECURE);
        }
        if (request)
        {
            DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy));
            const wchar_t headers[] =
                L"Content-Type: application/json; charset=utf-8\r\n"
                L"Accept: application/json\r\n";
            if (WinHttpSendRequest(
                    request,
                    headers,
                    static_cast<DWORD>(std::wcslen(headers)),
                    const_cast<char*>(body.data()),
                    static_cast<DWORD>(body.size()),
                    static_cast<DWORD>(body.size()),
                    0) &&
                WinHttpReceiveResponse(request, nullptr))
            {
                DWORD status = 0;
                DWORD status_size = sizeof(status);
                WinHttpQueryHeaders(
                    request,
                    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                    WINHTTP_HEADER_NAME_BY_INDEX,
                    &status,
                    &status_size,
                    WINHTTP_NO_HEADER_INDEX);
                if (status == 200)
                    result = heartbeat_state::active;
                else if (status == 403 || status == 401)
                    result = heartbeat_state::inactive;
            }
            WinHttpCloseHandle(request);
        }
        if (connection)
            WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session_handle);
        return result;
    }

    void report_violation(
        const std::wstring& url,
        const std::wstring& loader_id,
        const std::wstring& heartbeat_token,
        const char* reason)
    {
        std::string body;
        body += "{\"loader_id\":\"";
        for (const wchar_t character : loader_id)
            body.push_back(static_cast<char>(character));
        body += "\",\"heartbeat_token\":\"";
        for (const wchar_t character : heartbeat_token)
            body.push_back(static_cast<char>(character));
        body += "\",\"reason\":\"";
        for (const char* cursor = reason; *cursor; ++cursor)
        {
            if (*cursor == '"' || *cursor == '\\')
                body.push_back('\\');
            if (*cursor >= 0x20)
                body.push_back(*cursor);
        }
        body += "\"}";

        URL_COMPONENTS components{};
        components.dwStructSize = sizeof(components);
        components.dwHostNameLength = static_cast<DWORD>(-1);
        components.dwUrlPathLength = static_cast<DWORD>(-1);
        components.dwExtraInfoLength = static_cast<DWORD>(-1);
        if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &components) ||
            components.nScheme != INTERNET_SCHEME_HTTPS || !components.dwHostNameLength)
            return;

        HINTERNET session_handle = WinHttpOpen(
            L"patchwin.cc watchdog/1.0",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!session_handle)
            return;

        DWORD secure_protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(session_handle, WINHTTP_OPTION_SECURE_PROTOCOLS, &secure_protocols, sizeof(secure_protocols));
        WinHttpSetTimeouts(session_handle, 8000, 10000, 10000, 20000);

        const std::wstring host(components.lpszHostName, components.dwHostNameLength);
        HINTERNET connection = WinHttpConnect(session_handle, host.c_str(), components.nPort, 0);
        HINTERNET request = nullptr;
        if (connection)
        {
            request = WinHttpOpenRequest(
                connection,
                L"POST",
                L"/api/v1/loader/violation",
                nullptr,
                WINHTTP_NO_REFERER,
                nullptr,
                WINHTTP_FLAG_SECURE);
        }
        if (request)
        {
            DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy));
            const wchar_t headers[] =
                L"Content-Type: application/json; charset=utf-8\r\n"
                L"Accept: application/json\r\n";
            WinHttpSendRequest(
                request,
                headers,
                static_cast<DWORD>(std::wcslen(headers)),
                const_cast<char*>(body.data()),
                static_cast<DWORD>(body.size()),
                static_cast<DWORD>(body.size()),
                0);
            WinHttpReceiveResponse(request, nullptr);
            WinHttpCloseHandle(request);
        }
        if (connection)
            WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session_handle);
    }

    bool process_is_game(HANDLE process)
    {
        std::vector<wchar_t> path(32768);
        DWORD length = static_cast<DWORD>(path.size());
        if (!QueryFullProcessImageNameW(process, 0, path.data(), &length) || !length)
            return false;
        const std::wstring image(path.data(), length);
        const size_t separator = image.find_last_of(L"\\/");
        const std::wstring name = separator == std::wstring::npos
            ? image
            : image.substr(separator + 1);
        return _wcsicmp(name.c_str(), L"csgo.exe") == 0;
    }

    bool game_module_present(HANDLE process, const wchar_t* module_name)
    {
        HMODULE modules[1024]{};
        DWORD needed = 0;
        if (!EnumProcessModules(process, modules, sizeof(modules), &needed))
            return true;

        const DWORD count = needed / sizeof(HMODULE);
        for (DWORD index = 0; index < count; ++index)
        {
            wchar_t base_name[MAX_PATH]{};
            if (!GetModuleBaseNameW(process, modules[index], base_name, MAX_PATH))
                continue;
            if (_wcsicmp(base_name, module_name) == 0)
                return true;
        }
        return false;
    }

    void crash_game(HANDLE process)
    {
        TerminateProcess(process, 0xC0000409);
    }

    // Resident watchdog: monitors the game process after injection. Any external
    // interaction (debugger attached, protected module unloaded) or a revoked
    // license ends the game; tamper is additionally reported for an automatic ban.
    int run_watchdog(const DWORD game_pid)
    {
        const std::wstring url = read_env(L"NL_HEARTBEAT_URL");
        const std::wstring loader_id = read_env(L"NL_LOADER_ID");
        const std::wstring heartbeat_token = read_env(L"NL_HEARTBEAT_TOKEN");
        const bool license_bound = !url.empty() && !loader_id.empty() && !heartbeat_token.empty();

        unique_handle process(OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE,
            FALSE,
            game_pid));
        if (!process || !process_is_game(process.get()))
            return 0;

        const ULONGLONG module_deadline = GetTickCount64() + kWatchdogModuleWaitMs;
        bool module_confirmed = false;
        while (!module_confirmed && GetTickCount64() < module_deadline)
        {
            if (WaitForSingleObject(process.get(), 0) == WAIT_OBJECT_0)
                return 0;
            if (game_module_present(process.get(), L"neverlose.dll"))
                module_confirmed = true;
            else
                Sleep(2000);
        }
        if (!module_confirmed)
            return 0;

        DWORD consecutive_tamper = 0;
        for (;;)
        {
            Sleep(kWatchdogIntervalMs);

            if (WaitForSingleObject(process.get(), 0) == WAIT_OBJECT_0)
                return 0;
            if (!process_is_game(process.get()))
                return 0;

            BOOL debugged = FALSE;
            const bool debugger_on_game =
                CheckRemoteDebuggerPresent(process.get(), &debugged) && debugged;
            const bool module_missing = !game_module_present(process.get(), L"neverlose.dll");

            if (debugger_on_game || module_missing)
            {
                ++consecutive_tamper;
                if (consecutive_tamper >= kWatchdogTamperThreshold)
                {
                    if (license_bound)
                    {
                        report_violation(
                            url,
                            loader_id,
                            heartbeat_token,
                            debugger_on_game ? "debugger_attached" : "module_unloaded");
                    }
                    crash_game(process.get());
                    return 0;
                }
                continue;
            }
            consecutive_tamper = 0;

            if (license_bound)
            {
                const heartbeat_state state = query_heartbeat(url, loader_id, heartbeat_token);
                if (state == heartbeat_state::inactive)
                {
                    crash_game(process.get());
                    return 0;
                }
            }
        }
    }

    bool spawn_watchdog(const DWORD game_pid)
    {
        std::wstring self_path(32768, L'\0');
        const DWORD length = GetModuleFileNameW(nullptr, self_path.data(), static_cast<DWORD>(self_path.size()));
        if (!length || length >= self_path.size())
            return false;
        self_path.resize(length);

        std::wstring command_line = L"\"" + self_path + L"\" --watchdog " + std::to_wstring(game_pid);
        std::vector<wchar_t> writable(command_line.begin(), command_line.end());
        writable.push_back(L'\0');

        STARTUPINFOW startup_info{};
        startup_info.cb = sizeof(startup_info);
        PROCESS_INFORMATION process_info{};
        const BOOL spawned = CreateProcessW(
            self_path.c_str(),
            writable.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW | DETACHED_PROCESS,
            nullptr,
            nullptr,
            &startup_info,
            &process_info);
        if (!spawned)
            return false;

        if (process_info.hProcess)
            CloseHandle(process_info.hProcess);
        if (process_info.hThread)
            CloseHandle(process_info.hThread);
        return true;
    }
}

int main(const int argc, const char** argv)
{
    if (argc == 3 && std::strcmp(argv[1], "--watchdog") == 0)
    {
        const unsigned long watchdog_pid = std::stoul(argv[2]);
        return run_watchdog(static_cast<DWORD>(watchdog_pid));
    }

    print_banner();

    if (debugger_detected())
    {
        print_status("[-]", "Failed to initialize runtime.");
        return 1;
    }

    if (!verify_license_heartbeat())
        return 1;

    winsock_session winsock;
    if (!winsock.ready())
    {
        print_status("[-]", "Failed to initialize Winsock.");
        return 1;
    }

    char full_dll_path[MAX_PATH]{};
    DWORD process_id = 0;
    std::wstring cloud_path;

    if (!launch_game_if_needed())
        return 1;

    wait_for_game_window(process_id);
    std::printf("[+] Found CS:GO (PID: %lu)\n", process_id);

    if (!prepare_game_cloud_storage(process_id, cloud_path))
        return 1;

    if (!resolve_dll_path(full_dll_path))
    {
        print_status(
            "[-]",
            "No usable neverlose.dll was found next to the injector."
        );
        return 1;
    }

    std::printf("[+] DLL path: %s\n", full_dll_path);

    print_status("[*]", "Starting bundled patchwin.cc server...");
    if (!ensure_server(cloud_path))
        return 1;

    erase_own_pe_header();

    HANDLE process = OpenProcess(kProcessAccess, FALSE, process_id);
    if (!process || process == INVALID_HANDLE_VALUE)
    {
        print_status("[-]", "Failed to open process. Run as administrator.");
        return 1;
    }

    RestoreNtOpenFile(process);

    const SIZE_T path_length = std::strlen(full_dll_path) + 1;
    LPVOID remote_path = VirtualAllocEx(process, nullptr, path_length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote_path)
    {
        print_status("[-]", "VirtualAllocEx failed.");
        CloseHandle(process);
        return 1;
    }

    std::printf("[+] Allocated remote memory at 0x%p\n", remote_path);

    SIZE_T path_bytes_written = 0;
    if (!WriteProcessMemory(
            process,
            remote_path,
            full_dll_path,
            path_length,
            &path_bytes_written) ||
        path_bytes_written != path_length)
    {
        print_status("[-]", "WriteProcessMemory failed.");
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    HMODULE local_kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC local_load_library = local_kernel32
        ? GetProcAddress(local_kernel32, "LoadLibraryA")
        : nullptr;

    HMODULE local_load_module = nullptr;
    if (!local_load_library ||
        !GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(local_load_library),
            &local_load_module))
    {
        print_status("[-]", "Failed to resolve the LoadLibraryA owner module.");
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    wchar_t load_module_path[MAX_PATH]{};
    const DWORD load_module_length = GetModuleFileNameW(
        local_load_module,
        load_module_path,
        MAX_PATH);
    const wchar_t* load_module_name = wcsrchr(load_module_path, L'\\');
    load_module_name = load_module_name
        ? load_module_name + 1
        : load_module_path;
    LPVOID remote_load_module =
        load_module_length && load_module_length < MAX_PATH
        ? GetModBase(process_id, load_module_name)
        : nullptr;
    if (!remote_load_module)
    {
        print_status("[-]", "Failed to locate remote LoadLibraryA.");
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    auto remote_load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        reinterpret_cast<uintptr_t>(remote_load_module) +
        (reinterpret_cast<uintptr_t>(local_load_library) -
            reinterpret_cast<uintptr_t>(local_load_module)));
    std::printf(
        "[+] Remote LoadLibraryA at 0x%p\n",
        reinterpret_cast<void*>(remote_load_library));

    HANDLE remote_thread = CreateRemoteThread(
        process,
        nullptr,
        0,
        remote_load_library,
        remote_path,
        0,
        nullptr
    );

    if (!remote_thread || remote_thread == INVALID_HANDLE_VALUE)
    {
        print_status("[-]", "CreateRemoteThread failed.");
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    print_status("[*]", "Waiting for remote thread...");
    if (WaitForSingleObject(remote_thread, INFINITE) != WAIT_OBJECT_0)
    {
        print_status("[-]", "Failed while waiting for remote thread.");
        CloseHandle(remote_thread);
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    DWORD exit_code = 0;
    if (!GetExitCodeThread(remote_thread, &exit_code))
        exit_code = 0;
    std::printf("[+] LoadLibrary returned 0x%lX\n", exit_code);

    if (exit_code == 0)
    {
        print_status("[-]", "DLL failed to load. Check the path and architecture.");
        const DWORD dll_attributes = GetFileAttributesA(full_dll_path);

        int staging_length = MultiByteToWideChar(CP_ACP, 0, full_dll_path, -1, nullptr, 0);
        std::wstring staging_wide(staging_length > 0 ? staging_length : 1, L'\0');
        if (staging_length > 0)
            MultiByteToWideChar(CP_ACP, 0, full_dll_path, -1, staging_wide.data(), staging_length);
        const std::wstring staging_dir = parent_directory(staging_wide);

        if (dll_attributes == INVALID_FILE_ATTRIBUTES)
        {
            print_status("[-]", "DLL file is gone after the load attempt: antivirus quarantined it.");
            offer_protection_fix(staging_dir);
        }
        else
        {
            print_status("[-]", "DLL is present but Windows refused to load it (code integrity).");
            offer_protection_fix(staging_dir);
        }
    }
    else
        print_status("[+]", "DLL injected successfully.");

    VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
    CloseHandle(remote_thread);
    CloseHandle(process);

    if (exit_code != 0)
    {
        if (spawn_watchdog(process_id))
            print_status("[+]", "Runtime protection started.");
        else
            print_status("[!]", "Runtime protection could not start.");
    }

    std::puts("");
    print_status("[*]", "Closing in 2 seconds...");
    Sleep(2000);
    return exit_code == 0 ? 1 : 0;
}
