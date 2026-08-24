#include <intrin.h>

#include "internal_fixes.h"
#include "neverlosesdk.hpp"
#include "HookFn.h"
#include "token.h"
#include <cstdarg>
#include <climits>
#include <string>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#define GHETTO_FIX

#ifdef GHETTO_FIX

static HINTERNET hSession = NULL;
static HINTERNET hConnection = NULL;

#if defined(_DEBUG) || defined(NLR_ENABLE_REQUESTOR_DIAGNOSTICS)
static void requestor_log(const char* fmt, ...)
{
    char path[MAX_PATH]{};
    if (!GetTempPathA(MAX_PATH, path))
        return;
    strcat_s(path, "nl_requestor_debug.log");

    HANDLE file = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return;

    char line[2048]{};
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf_s(line, sizeof(line), _TRUNCATE, fmt, args);
    va_end(args);

    if (len < 0)
        len = static_cast<int>(strnlen_s(line, sizeof(line)));

    if (len > 0)
    {
        DWORD written = 0;
        WriteFile(file, line, len, &written, nullptr);
    }

    CloseHandle(file);
}
#define REQUESTOR_LOG(...) requestor_log(__VA_ARGS__)
#define REQUESTOR_PRINTF(...) printf(__VA_ARGS__)
#else
#define REQUESTOR_LOG(...) ((void)0)
#define REQUESTOR_PRINTF(...) ((void)0)
#endif

void __fastcall GetSerial(void* ecx, void* edx, std::string& out, nlohmann::json& request)
{
    /*
    Request: {"params":{"hash":"N9xnoBk9JkbYQ66WTtgAAAAAAAD/AP8AeaCdFAAAAAA=","hash2":"hKV0twE0V3XnSatdohvL8nJXRuIWjzJCUnQidy4ttcjiAa4N6nUi2Q=="},"type":4}
    Mine hash : sft4Nhk9JkYCUHF3UYgAACHJkIv/AP8Aa8mGuAAAAAA=, hash2: hKV0t81t04fnSatdTmWcTKLf9ZQ=
     */
    new (&out) std::string("g6w/cgN2AuDsLw3xrzboM1kbkLy+osvg0Y/j0LJnQf04GHbV8s5V4yReEk1mh3ZA2G72fHG3oOh7zlGEfR1nKw717WiwRwsrgSDfJtaTQz14VDDkayLBNV1DaT/qSyx8Frg1nXU0crRu1P/G+EPvH6nWNPYLZdUMIeqVCToEFhJnqiuRoAyypjFNiKnLEMiy5j2YvBcLCOC8yC3FPt/GGsvUldBqkmQGkBjIsXsSkut05txVxq7VDx1i9adKE4zalTzNHr0Vtd6DTr8aeH8NYHWPGWAsnTBkZlkNuRuhBTtgRTcIKxzGATTN4k8/JaXCpxri7IqsylvZgXQw+5zldLjAHqcAWw3OD5iQn8DtOoon+DrHm3k3FY6wIrCM1FzTdjAIcTvXSiWOURHiwA4sJ8ExR4dyBZMydo8aBAYjrRxcD9oDa/VVJT4cZfDkyWvRjI3WMyEajF2JhiGcjpjztmD8fyt9C16VXwLfoYuJnrX1/Dv8SZfCU6U2UhwJlxO5mkg+/IctveCdxy8IIiXTKwA5vmiEpXRuUu17SCdmJhFLZ+Jr6cTmrob4exSEggGRk6BTaVomOq4I6IpkVUBIUVup+4JvWFseL5UkPOQqHIO5Rxnj1jY+PjAWFPeeXSZsP8/ceEnX8J13tfb7PAqRSrpQ1Wv/y+OjaqMoPg9PiRE=");
    REQUESTOR_PRINTF("Spoofed serial %s\n", request.dump().c_str());
};

void __fastcall MakeRequest(void* ecx, void* edx, std::string& out, std::string_view route, int _, int __)
{
    REQUESTOR_PRINTF("[0x%p] 0x%p MakeRequest(%.*s, 0x%X, 0x%X) spoofed\n",
        NtCurrentThreadId(), _ReturnAddress(), (int)route.size(), route.data(), _, __);
    REQUESTOR_LOG("[0x%p] 0x%p raw MakeRequest(%.*s, 0x%X, 0x%X)\n",
        NtCurrentThreadId(), _ReturnAddress(), (int)route.size(), route.data(), _, __);

    new (&out) std::string("");

    HINTERNET hRequest = nullptr;
    if (route.size() <= static_cast<size_t>(INT_MAX))
    {
        std::wstring wroute;
        bool route_converted = route.empty();
        if (!route.empty())
        {
            const int route_length = static_cast<int>(route.size());
            const int size_needed = MultiByteToWideChar(
                CP_UTF8, 0, route.data(), route_length, nullptr, 0);
            if (size_needed > 0)
            {
                wroute.resize(size_needed);
                route_converted = MultiByteToWideChar(
                    CP_UTF8,
                    0,
                    route.data(),
                    route_length,
                    wroute.data(),
                    size_needed) == size_needed;
            }
        }

        if (route_converted && hConnection)
        {
            hRequest = WinHttpOpenRequest(
                hConnection,
                L"GET",
                wroute.c_str(),
                nullptr,
                WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                0);
        }

        if (hRequest && WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        {
            if (WinHttpReceiveResponse(hRequest, NULL))
            {
                DWORD dwSize = 0;
                DWORD dwDownloaded = 0;

                do
                {
                    dwSize = 0;
                    if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0) break;

                    size_t oldSize = out.size();
                    out.resize(oldSize + dwSize);

                    if (!WinHttpReadData(hRequest, &out[oldSize], dwSize, &dwDownloaded))
                    {
                        out.resize(oldSize);
                        break;
                    };

                    if (dwDownloaded < dwSize)
                        out.resize(oldSize + dwDownloaded);
                    if (dwDownloaded == 0)
                        break;

                } while (dwSize > 0);
            };
        };
    }

    if (hRequest)
        WinHttpCloseHandle(hRequest);

    int preview_len = (int)(out.size() < 96 ? out.size() : 96);
    REQUESTOR_LOG("[0x%p] raw MakeRequest returned %zu bytes: %.*s\n",
        NtCurrentThreadId(),
        out.size(),
        preview_len,
        out.data());
};

void __fastcall Libreq(void* ecx, void* edx, std::string& out, std::string_view libname)
{
    REQUESTOR_LOG("[0x%p] raw QueryLuaLibrary(%.*s)\n", NtCurrentThreadId(), (int)libname.size(), libname.data());
    new (&out) std::string(libname);
};

void hijack_requestor()
{
    REQUESTOR_LOG("[0x%p] hijack_requestor installing raw thunk hooks\n", NtCurrentThreadId());
    hSession = WinHttpOpen(L"NLR/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession)
        hConnection = WinHttpConnect(hSession, L"127.0.0.1", 30031, 0); // test.zx9.lol >.<
    REQUESTOR_LOG("[0x%p] raw hSession=0x%p hConnection=0x%p\n", NtCurrentThreadId(), hSession, hConnection);
    const NTSTATUS serial_hook = HookFn((PVOID)0x41BC78E0, GetSerial, 0);
    const NTSTATUS request_hook = HookFn((PVOID)0x41BC98E0, MakeRequest, 0);
    REQUESTOR_LOG(
        "[0x%p] hook status serial=0x%08lX request=0x%08lX\n",
        NtCurrentThreadId(),
        serial_hook,
        request_hook);
    // Let the real QueryLuaLibrary run. It updates internal requestor/library state;
    // bypassing it returns the right name but leaves the caller wedged after reqitem.
    REQUESTOR_LOG("[0x%p] hijack_requestor leaving QueryLuaLibrary unhooked\n", NtCurrentThreadId());
    REQUESTOR_LOG("[0x%p] hijack_requestor installed raw thunk hooks\n", NtCurrentThreadId());
};

#undef REQUESTOR_PRINTF
#undef REQUESTOR_LOG

#else // !GHETTO_FIX

static void requestor_log(const char* fmt, ...)
{
    char path[MAX_PATH]{};
    if (!GetTempPathA(MAX_PATH, path))
        return;
    strcat_s(path, "nl_requestor_debug.log");

    HANDLE file = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return;

    char line[2048]{};
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf_s(line, sizeof(line), _TRUNCATE, fmt, args);
    va_end(args);

    if (len < 0)
        len = static_cast<int>(strnlen_s(line, sizeof(line)));

    if (len > 0)
    {
        DWORD written = 0;
        WriteFile(file, line, len, &written, nullptr);
    }

    CloseHandle(file);
}

void* reqtram = 0;
void* hkReqInst()
{
    printf("[0x%p] 0x%p Requestor::Instance\n", NtCurrentThreadId(), _ReturnAddress());
    requestor_log("[0x%p] 0x%p Requestor::Instance\n", NtCurrentThreadId(), _ReturnAddress());
    //return *(PPVOID)0x42518C58;
    return reinterpret_cast<decltype(&hkReqInst)>(reqtram)();
};


class NLR_Requestor : public neverlosesdk::network::Requestor
{
	HINTERNET hSession;
	HINTERNET hConnection;

    static std::string with_token(std::string_view route)
    {
        std::string resolved(route);

        if (!auth_token || !auth_token[0])
            return resolved;

        if (resolved.find("token=") != std::string::npos)
            return resolved;

        if (!resolved.empty() && resolved[0] == '/')
            resolved += (resolved.find('?') == std::string::npos) ? '?' : '&';
        else
            return resolved;

        resolved += "token=";
        resolved += auth_token;
        return resolved;
    }

    void MakeRequest(std::string& out, std::string_view route, int _, int __) override
    {
        const std::string resolved_route = with_token(route);
        printf("[0x%p] 0x%p MakeRequest(%.*s, 0x%X, 0x%X) spoofed\n",
            NtCurrentThreadId(),
            _ReturnAddress(),
            (int)resolved_route.size(),
            resolved_route.data(),
            _,
            __);
        fflush(stdout);
        requestor_log("[0x%p] 0x%p MakeRequest(%.*s, 0x%X, 0x%X)\n",
            NtCurrentThreadId(),
            _ReturnAddress(),
            (int)resolved_route.size(),
            resolved_route.data(),
            _,
            __);

        new (&out) std::string("");

        int size_needed = MultiByteToWideChar(CP_UTF8, 0, resolved_route.data(), (int)resolved_route.size(), NULL, 0);
        wchar_t* wroute = (wchar_t*)malloc((size_needed + 1) * sizeof(wchar_t));

        if (wroute)
        {
            MultiByteToWideChar(CP_UTF8, 0, resolved_route.data(), (int)resolved_route.size(), wroute, size_needed);
            wroute[size_needed] = L'\0';
            HINTERNET hRequest = WinHttpOpenRequest(hConnection, L"GET", wroute, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            free(wroute);
            if (hRequest && WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
            {
                if (WinHttpReceiveResponse(hRequest, NULL))
                {
                    DWORD status = 0;
                    DWORD status_size = sizeof(status);
                    WinHttpQueryHeaders(
                        hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &status,
                        &status_size,
                        WINHTTP_NO_HEADER_INDEX
                    );
                    printf("[0x%p] MakeRequest status=%lu\n", NtCurrentThreadId(), status);
                    fflush(stdout);
                    requestor_log("[0x%p] MakeRequest status=%lu\n", NtCurrentThreadId(), status);

                    DWORD dwSize = 0;
                    DWORD dwDownloaded = 0;

                    do
                    {
                        dwSize = 0;
                        if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0) break;

                        size_t oldSize = out.size();
                        out.resize(oldSize + dwSize);

                        if (!WinHttpReadData(hRequest, &out[oldSize], dwSize, &dwDownloaded))
                        {
                            out.resize(oldSize);
                            break;
                        };

                        if (dwDownloaded < dwSize)
                            out.resize(oldSize + dwDownloaded);

                    } while (dwSize > 0);
                };
            };
            WinHttpCloseHandle(hRequest);
        };
        printf("[0x%p] MakeRequest returned %zu bytes\n", NtCurrentThreadId(), out.size());
        fflush(stdout);
        requestor_log("[0x%p] MakeRequest returned %zu bytes\n", NtCurrentThreadId(), out.size());
    };
    /*
    Request: {"params":{"hash":"N9xnoBk9JkbYQ66WTtgAAAAAAAD/AP8AeaCdFAAAAAA=","hash2":"hKV0twE0V3XnSatdohvL8nJXRuIWjzJCUnQidy4ttcjiAa4N6nUi2Q=="},"type":4}
    Mine hash : sft4Nhk9JkYCUHF3UYgAACHJkIv/AP8Aa8mGuAAAAAA=, hash2: hKV0t81t04fnSatdTmWcTKLf9ZQ=
    */
    void GetSerial(std::string& out, nlohmann::json& request) override
    {


        printf("[GetSerial] called from 0x%p\n", _ReturnAddress()); fflush(stdout);
        // __try
        // {
            printf("[GetSerial] request: %s\n", request.dump().c_str()); fflush(stdout);
            if (request.contains("params"))
            {
                auto& p = request["params"];
                if (p.contains("hash"))
                    printf("[GetSerial] hash:  %s\n", p["hash"].get<std::string>().c_str());
                if (p.contains("hash2"))
                    printf("[GetSerial] hash2: %s\n", p["hash2"].get<std::string>().c_str());
                fflush(stdout);
            }
            if (auth_token && auth_token[0])
                printf("[GetSerial] using website token (%zu bytes)\n", strlen(auth_token));
        // }
        // __except (EXCEPTION_EXECUTE_HANDLER)
        // {
        //     printf("[GetSerial] WARNING: crashed reading request (debug/release STL mismatch?)\n"); fflush(stdout);
        // }
        new (&out) std::string("g6w/cgN2AuDsLw3xrzboM1kbkLy+osvg0Y/j0LJnQf04GHbV8s5V4yReEk1mh3ZA2G72fHG3oOh7zlGEfR1nKw717WiwRwsrgSDfJtaTQz14VDDkayLBNV1DaT/qSyx8Frg1nXU0crRu1P/G+EPvH6nWNPYLZdUMIeqVCToEFhJnqiuRoAyypjFNiKnLEMiy5j2YvBcLCOC8yC3FPt/GGsvUldBqkmQGkBjIsXsSkut05txVxq7VDx1i9adKE4zalTzNHr0Vtd6DTr8aeH8NYHWPGWAsnTBkZlkNuRuhBTtgRTcIKxzGATTN4k8/JaXCpxri7IqsylvZgXQw+5zldLjAHqcAWw3OD5iQn8DtOoon+DrHm3k3FY6wIrCM1FzTdjAIcTvXSiWOURHiwA4sJ8ExR4dyBZMydo8aBAYjrRxcD9oDa/VVJT4cZfDkyWvRjI3WMyEajF2JhiGcjpjztmD8fyt9C16VXwLfoYuJnrX1/Dv8SZfCU6U2UhwJlxO5mkg+/IctveCdxy8IIiXTKwA5vmiEpXRuUu17SCdmJhFLZ+Jr6cTmrob4exSEggGRk6BTaVomOq4I6IpkVUBIUVup+4JvWFseL5UkPOQqHIO5Rxnj1jY+PjAWFPeeXSZsP8/ceEnX8J13tfb7PAqRSrpQ1Wv/y+OjaqMoPg9PiRE=");
        printf("[GetSerial] returned serial (%zu bytes)\n", out.size()); fflush(stdout);
    };
    void fn2() override
    {
        printf("[0x%p] 0x%p fn2() called (ignored)\n", NtCurrentThreadId(), _ReturnAddress());
        fflush(stdout);
        // fn2 is never called in analyzed code - safe to no-op
    };

    // fn3 is the WebSocket data method - called for config, lua scripts, auth, entity data, etc.
    // The json& request param contains {"type": N, "params": {...}}
    // We log it and return an empty response to avoid crashes/hangs.
    void fn3(std::string& out, nlohmann::json& request) override
    {


        int type = -1;
        if (request.contains("type"))
            type = request["type"].get<int>();

        printf("[0x%p] 0x%p fn3(type=%d) called\n", NtCurrentThreadId(), _ReturnAddress(), type);
        fflush(stdout);

        // Return empty JSON object - callers check for specific fields
        // and handle missing ones gracefully in most cases.
        new (&out) std::string("{}");
    };

    // QueryLuaLibrary: fetch Lua script source from HTTP server.
    // Previous impl just returned name as-is (the lua VM would try to "require" a filename, not actual code).
    void QueryLuaLibrary(std::string& out, std::string_view name) override
    {


        printf("[0x%p] QueryLuaLibrary(%.*s) fetching...\n",
            NtCurrentThreadId(), (int)name.size(), name.data());
        fflush(stdout);
        requestor_log("[0x%p] QueryLuaLibrary(%.*s) fetching\n",
            NtCurrentThreadId(), (int)name.size(), name.data());

        new (&out) std::string(name);
        requestor_log("[0x%p] QueryLuaLibrary name-only -> %zu bytes: %.*s\n",
            NtCurrentThreadId(),
            out.size(),
            (int)out.size(),
            out.data());
        return;

        // Build the route string: /lua/<name>?token=<token>&cheat=csgo
        std::string route = "/lua/";
        route.append(name.data(), name.size());
        route += "?cheat=csgo";
        route = with_token(route);

        int size_needed = MultiByteToWideChar(CP_UTF8, 0, route.data(), (int)route.size(), NULL, 0);
        wchar_t* wroute = (wchar_t*)malloc((size_needed + 1) * sizeof(wchar_t));

        new (&out) std::string("");

        if (wroute)
        {
            MultiByteToWideChar(CP_UTF8, 0, route.data(), (int)route.size(), wroute, size_needed);
            wroute[size_needed] = L'\0';
            HINTERNET hRequest = WinHttpOpenRequest(hConnection, L"GET", wroute, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            free(wroute);
            if (hRequest && WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
            {
                if (WinHttpReceiveResponse(hRequest, NULL))
                {
                    DWORD dwSize = 0;
                    DWORD dwDownloaded = 0;
                    do
                    {
                        dwSize = 0;
                        if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0) break;
                        size_t oldSize = out.size();
                        out.resize(oldSize + dwSize);
                        if (!WinHttpReadData(hRequest, &out[oldSize], dwSize, &dwDownloaded))
                        {
                            out.resize(oldSize);
                            break;
                        };
                        if (dwDownloaded < dwSize)
                            out.resize(oldSize + dwDownloaded);
                    } while (dwSize > 0);
                };
            };
            WinHttpCloseHandle(hRequest);
        };

        if (out.empty())
        {
            // Fallback: return empty lua comment so the VM doesn't error
            out = "-- lua library: ";
            out.append(name.data(), name.size());
            out += "\n";
        }

        int preview_len = (int)(out.size() < 80 ? out.size() : 80);
        printf("[0x%p] QueryLuaLibrary(%.*s) -> %zu bytes: %.*s\n",
            NtCurrentThreadId(),
            (int)name.size(),
            name.data(),
            out.size(),
            preview_len,
            out.data());
        fflush(stdout);
        requestor_log("[0x%p] QueryLuaLibrary(%.*s) -> %zu bytes: %.*s\n",
            NtCurrentThreadId(),
            (int)name.size(),
            name.data(),
            out.size(),
            preview_len,
            out.data());
    };

public:
    NLR_Requestor() : hSession(NULL), hConnection(NULL)
    {


        requestor_log("[0x%p] NLR_Requestor ctor token_present=%d\n", NtCurrentThreadId(), auth_token && auth_token[0]);
        hSession = WinHttpOpen(L"NLR/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession)
            hConnection = WinHttpConnect(hSession, L"127.0.0.1", 30031, 0); // test.zx9.lol
        requestor_log("[0x%p] NLR_Requestor hSession=0x%p hConnection=0x%p\n", NtCurrentThreadId(), hSession, hConnection);
    };
};

void hijack_requestor()
{
    requestor_log("[0x%p] hijack_requestor installing\n", NtCurrentThreadId());
    *(neverlosesdk::network::Requestor**)0x42518C58 = new NLR_Requestor;
    *(PDWORD)0x42518C54 = 0x80000004;
    HookFn((PVOID)0x41BC9450, hkReqInst, 0, &reqtram);
    requestor_log("[0x%p] hijack_requestor installed reqtram=0x%p\n", NtCurrentThreadId(), reqtram);
};

#endif // GHETTO_FIX
