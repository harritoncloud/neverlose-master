#include "neverlose.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <intrin.h>

#include "fix_persist.h"
#include "fix_rage_records.h"
#include "rage_record_logic.h"

namespace
{
constexpr std::uintptr_t kBuildBase = 0x412A0000;
constexpr std::uint8_t kRecordWindowSize = 4;
constexpr std::uint16_t kRecordTerminationMask = 0x0808;

constexpr std::uintptr_t kFnRecordExpired = 0x413F6D50;
constexpr std::uintptr_t kFnWindowCheck = 0x41400BF0;
constexpr std::uintptr_t kFnTickDelta = 0x413341E0;
constexpr std::uintptr_t kFnRecordLookup = 0x4135F0E0;
constexpr std::uintptr_t kWindowContext = 0x424B004C;
constexpr std::uintptr_t kBtScoreLookup = 0x424B1C98;

constexpr std::uintptr_t kCustomRecordAccept = 0x4148F2AF;
constexpr std::uintptr_t kCustomRecordContinue = 0x4148F527;
constexpr std::uintptr_t kShotEntityFallthrough = 0x4148F1AC;
constexpr std::uintptr_t kShotEntityValid = 0x4148F1D2;

constexpr std::uint32_t kMaximumPlayerIndex = 64;
constexpr std::uint32_t kBtScoreStride = 0x44;
constexpr std::uint32_t kLagRecordStride = 0x10940;
constexpr std::uint32_t kShotSearchPairs = kRecordWindowSize;
constexpr std::uint32_t kShotContextRetryMilliseconds = 1000;
constexpr std::uint32_t kMaximumNetvarOffset = 0x10000;
constexpr std::size_t kRecordSimulationTimeOffset = 0x24;

using record_expired_fn = bool(__thiscall*)(void*);
using window_check_fn = bool(__thiscall*)(
    void*,
    std::uint32_t,
    float,
    std::uint8_t*,
    std::uint32_t,
    std::uint32_t);
using tick_delta_fn = int(__cdecl*)(std::uint32_t, std::uint32_t);
using record_lookup_fn = void*(__thiscall*)(void*, std::int32_t);

struct bt_score_state
{
    bool readable = false;
    bool classified = false;
    bool pending = false;
};

struct recv_table;

struct recv_prop
{
    const char* name;
    int type;
    int flags;
    int string_buffer_size;
    std::uint8_t inside_array;
    std::uint8_t padding[3];
    const void* extra_data;
    recv_prop* array_prop;
    void* array_length_proxy;
    void* proxy;
    void* data_table_proxy;
    recv_table* data_table;
    int offset;
    int element_stride;
    int elements;
    const char* parent_array_prop_name;
};

struct recv_table
{
    recv_prop* props;
    int prop_count;
    void* decoder;
    const char* name;
    std::uint8_t initialized;
    std::uint8_t in_main_list;
};

struct client_class
{
    void* create;
    void* create_event;
    const char* network_name;
    recv_table* table;
    client_class* next;
    int class_id;
};

static_assert(sizeof(void*) == 4);
static_assert(offsetof(recv_prop, data_table) == 0x28);
static_assert(offsetof(recv_prop, offset) == 0x2C);
static_assert(offsetof(recv_table, name) == 0x0C);
static_assert(offsetof(client_class, table) == 0x0C);
static_assert(offsetof(client_class, next) == 0x10);

using create_interface_fn = void*(__cdecl*)(const char*, int*);
using get_all_classes_fn = client_class*(__thiscall*)(void*);
using get_client_entity_fn = void*(__thiscall*)(void*, int);
using get_client_entity_from_handle_fn =
    void*(__thiscall*)(void*, std::uint32_t);

struct shot_context
{
    void* entity_list = nullptr;
    std::uint32_t active_weapon_offset = 0;
    std::uint32_t last_shot_time_offset = 0;
};

shot_context g_shot_context{};
volatile LONG g_shot_context_state = 0;
alignas(8) volatile LONG64 g_shot_context_next_probe = 0;
volatile LONG g_selected_entity_index = 0;
volatile LONG g_tick_delta_tls_index = static_cast<LONG>(TLS_OUT_OF_INDEXES);

constexpr std::uintptr_t kRetryTokenMarker = 0x01;
constexpr unsigned kRetryTokenRequestedShift = 1;
constexpr unsigned kRetryTokenAdjustedShift = 4;
constexpr unsigned kRetryTokenPathShift = 7;

enum class retry_path : std::uintptr_t
{
    none = 0,
    path_2 = 1,
    path_7 = 2,
    path_8 = 3,
};

retry_path tick_retry_path(std::uintptr_t return_address)
{
    switch (return_address)
    {
    case 0x414002A9:
        return retry_path::path_2;
    case 0x4149FA4A:
        return retry_path::path_7;
    case 0x414A8F5A:
        return retry_path::path_8;
    default:
        return retry_path::none;
    }
}

retry_path lookup_retry_path(std::uintptr_t return_address)
{
    switch (return_address)
    {
    case 0x414002BD:
        return retry_path::path_2;
    case 0x4149FA55:
        return retry_path::path_7;
    case 0x414A8F6E:
        return retry_path::path_8;
    default:
        return retry_path::none;
    }
}

std::uintptr_t make_retry_token(
    std::int32_t requested_delta,
    std::int32_t adjusted_delta,
    retry_path path)
{
    return kRetryTokenMarker |
        (static_cast<std::uintptr_t>(requested_delta) <<
            kRetryTokenRequestedShift) |
        (static_cast<std::uintptr_t>(adjusted_delta + 1) <<
            kRetryTokenAdjustedShift) |
        (static_cast<std::uintptr_t>(path) << kRetryTokenPathShift);
}

bool read_retry_token(
    std::uintptr_t token,
    std::int32_t observed_delta,
    retry_path expected_path,
    std::int32_t& requested_delta)
{
    if ((token & kRetryTokenMarker) == 0 ||
        expected_path == retry_path::none)
        return false;

    const auto requested = static_cast<std::int32_t>(
        (token >> kRetryTokenRequestedShift) & 0x07);
    const auto adjusted = static_cast<std::int32_t>(
        (token >> kRetryTokenAdjustedShift) & 0x07) - 1;
    const auto path = static_cast<retry_path>(
        (token >> kRetryTokenPathShift) & 0x03);
    if (path != expected_path || adjusted != observed_delta ||
        !rage_record_logic::should_retry_original_tick(
            requested,
            adjusted,
            observed_delta,
            kRecordWindowSize))
    {
        return false;
    }

    requested_delta = requested;
    return true;
}

bool ensure_tick_delta_tls()
{
    if (InterlockedCompareExchange(
            &g_tick_delta_tls_index,
            0,
            0) != static_cast<LONG>(TLS_OUT_OF_INDEXES))
    {
        return true;
    }

    const DWORD allocated = TlsAlloc();
    if (allocated == TLS_OUT_OF_INDEXES)
        return false;

    const LONG previous = InterlockedCompareExchange(
        &g_tick_delta_tls_index,
        static_cast<LONG>(allocated),
        static_cast<LONG>(TLS_OUT_OF_INDEXES));
    if (previous != static_cast<LONG>(TLS_OUT_OF_INDEXES))
        TlsFree(allocated);

    return true;
}

void publish_retry_token(
    std::int32_t requested_delta,
    std::int32_t native_delta,
    std::int32_t returned_delta,
    retry_path path)
{
    const LONG index = InterlockedCompareExchange(
        &g_tick_delta_tls_index,
        0,
        0);
    if (index == static_cast<LONG>(TLS_OUT_OF_INDEXES))
        return;

    const std::uintptr_t token =
        rage_record_logic::should_retry_original_tick(
            requested_delta,
            native_delta,
            returned_delta,
            kRecordWindowSize)
        ? make_retry_token(requested_delta, returned_delta, path)
        : 0;
    TlsSetValue(
        static_cast<DWORD>(index),
        reinterpret_cast<void*>(token));
}

std::uintptr_t consume_retry_token()
{
    const LONG index = InterlockedCompareExchange(
        &g_tick_delta_tls_index,
        0,
        0);
    if (index == static_cast<LONG>(TLS_OUT_OF_INDEXES))
        return 0;

    const DWORD tls_index = static_cast<DWORD>(index);
    const std::uintptr_t token = reinterpret_cast<std::uintptr_t>(
        TlsGetValue(tls_index));
    TlsSetValue(tls_index, nullptr);
    return token;
}

bool native_record_expired(void* record)
{
    return reinterpret_cast<record_expired_fn>(kFnRecordExpired)(record);
}

bool record_expired_strict(void* record)
{
    if (!record)
        return true;
    return native_record_expired(record);
}

bool record_is_usable(void* record)
{
    if (!record)
        return false;

    const auto* bytes = static_cast<volatile const std::uint8_t*>(record);
    return bytes[0xA4] != 0 &&
        (*reinterpret_cast<volatile const std::uint16_t*>(bytes + 0xB0) &
            kRecordTerminationMask) == 0 &&
        !record_expired_strict(record);
}

bool names_equal(const char* left, const char* right)
{
    return left && right && std::strcmp(left, right) == 0;
}

int find_property_offset(
    recv_table* table,
    const char* property_name,
    int accumulated_offset,
    unsigned depth)
{
    if (!table || !property_name || depth >= 16 ||
        !table->props || table->prop_count <= 0 ||
        table->prop_count > 4096)
    {
        return -1;
    }

    for (int index = 0; index < table->prop_count; ++index)
    {
        recv_prop& property = table->props[index];
        if (property.offset < 0 ||
            property.offset >= static_cast<int>(kMaximumNetvarOffset) ||
            accumulated_offset >
                static_cast<int>(kMaximumNetvarOffset) - property.offset)
        {
            continue;
        }

        const int complete_offset = accumulated_offset + property.offset;
        if (names_equal(property.name, property_name))
            return complete_offset;

        if (property.data_table && property.data_table != table)
        {
            const int nested = find_property_offset(
                property.data_table,
                property_name,
                complete_offset,
                depth + 1);
            if (nested >= 0)
                return nested;
        }
    }

    return -1;
}

recv_table* find_named_table(client_class* classes, const char* table_name)
{
    unsigned visited = 0;
    for (client_class* current = classes;
         current && visited < 512;
         current = current->next, ++visited)
    {
        if (current->table && names_equal(current->table->name, table_name))
            return current->table;
    }
    return nullptr;
}

int find_netvar_offset(
    client_class* classes,
    const char* property_name,
    const char* const* preferred_tables,
    std::size_t preferred_table_count)
{
    for (std::size_t index = 0; index < preferred_table_count; ++index)
    {
        recv_table* table = find_named_table(classes, preferred_tables[index]);
        const int offset = find_property_offset(
            table,
            property_name,
            0,
            0);
        if (offset > 0)
            return offset;
    }

    unsigned visited = 0;
    for (client_class* current = classes;
         current && visited < 512;
         current = current->next, ++visited)
    {
        const int offset = find_property_offset(
            current->table,
            property_name,
            0,
            0);
        if (offset > 0)
            return offset;
    }
    return -1;
}

bool resolve_shot_context(shot_context& resolved)
{
    HMODULE client_module = GetModuleHandleW(L"client.dll");
    if (!client_module)
        return false;

    bool success = false;
    __try
    {
        auto create_interface = reinterpret_cast<create_interface_fn>(
            GetProcAddress(client_module, "CreateInterface"));
        if (!create_interface)
            __leave;

        void* client = create_interface("VClient018", nullptr);
        void* entity_list = create_interface(
            "VClientEntityList003",
            nullptr);
        if (!client || !entity_list)
            __leave;

        auto** client_vtable = *reinterpret_cast<void***>(client);
        if (!client_vtable || !client_vtable[8])
            __leave;

        auto get_all_classes = reinterpret_cast<get_all_classes_fn>(
            client_vtable[8]);
        client_class* classes = get_all_classes(client);
        if (!classes)
            __leave;

        constexpr const char* active_weapon_tables[] = {
            "DT_CSPlayer",
            "DT_BasePlayer",
            "DT_BaseCombatCharacter"
        };
        constexpr const char* last_shot_tables[] = {
            "DT_WeaponCSBase",
            "DT_WeaponCSBaseGun",
            "DT_BaseCombatWeapon"
        };

        const int active_weapon_offset = find_netvar_offset(
            classes,
            "m_hActiveWeapon",
            active_weapon_tables,
            std::size(active_weapon_tables));
        const int last_shot_time_offset = find_netvar_offset(
            classes,
            "m_fLastShotTime",
            last_shot_tables,
            std::size(last_shot_tables));

        if (active_weapon_offset <= 0 ||
            last_shot_time_offset <= 0 ||
            active_weapon_offset >=
                static_cast<int>(kMaximumNetvarOffset) ||
            last_shot_time_offset >=
                static_cast<int>(kMaximumNetvarOffset) ||
            (active_weapon_offset & 3) != 0 ||
            (last_shot_time_offset & 3) != 0)
        {
            __leave;
        }

        resolved.entity_list = entity_list;
        resolved.active_weapon_offset = static_cast<std::uint32_t>(
            active_weapon_offset);
        resolved.last_shot_time_offset = static_cast<std::uint32_t>(
            last_shot_time_offset);
        success = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        success = false;
    }

    return success;
}

bool initialize_shot_context()
{
    const LONG state = InterlockedCompareExchange(
        &g_shot_context_state,
        0,
        0);
    if (state == 2)
        return true;
    if (state != 0 ||
        InterlockedCompareExchange(&g_shot_context_state, 1, 0) != 0)
    {
        return false;
    }

    shot_context resolved{};
    const bool ready = resolve_shot_context(resolved);
    if (ready)
        g_shot_context = resolved;

    InterlockedExchange(&g_shot_context_state, ready ? 2 : 0);
    return ready;
}

void probe_shot_context(bool force)
{
    if (InterlockedCompareExchange(&g_shot_context_state, 0, 0) != 0)
        return;

    const LONG64 now = static_cast<LONG64>(GetTickCount64());
    const LONG64 next = InterlockedCompareExchange64(
        &g_shot_context_next_probe,
        0,
        0);
    if (!force && now < next)
        return;

    const LONG64 new_deadline = now + kShotContextRetryMilliseconds;
    if (!force && InterlockedCompareExchange64(
            &g_shot_context_next_probe,
            new_deadline,
            next) != next)
    {
        return;
    }
    if (force)
        InterlockedExchange64(&g_shot_context_next_probe, new_deadline);

    initialize_shot_context();
}

bool plausible_pointer(const void* pointer)
{
    return reinterpret_cast<std::uintptr_t>(pointer) >= 0x10000;
}

bt_score_state read_bt_score_state(std::uint32_t entity_index)
{
    bt_score_state snapshot{};
    if (entity_index == 0 || entity_index > kMaximumPlayerIndex)
        return snapshot;

    auto* table = *reinterpret_cast<std::uint8_t* volatile const*>(
        kBtScoreLookup);
    if (!plausible_pointer(table))
        return snapshot;

    const std::uintptr_t table_address =
        reinterpret_cast<std::uintptr_t>(table);
    const std::uintptr_t state_address = table_address +
        static_cast<std::uintptr_t>(entity_index) * kBtScoreStride;
    if (state_address < table_address)
        return snapshot;

    const auto* state = reinterpret_cast<volatile const std::uint8_t*>(
        state_address);
    snapshot.readable = true;
    snapshot.classified = state[0x08] != 0;
    snapshot.pending = state[0x0A] != 0;
    return snapshot;
}

void* find_entity_shot_record_unchecked(
    std::uint32_t entity_index,
    void* validated_candidate)
{
    const shot_context context = g_shot_context;
    if (!plausible_pointer(context.entity_list))
        return nullptr;

    auto** entity_list_vtable =
        *reinterpret_cast<void***>(context.entity_list);
    if (!plausible_pointer(entity_list_vtable) ||
        !plausible_pointer(entity_list_vtable[3]) ||
        !plausible_pointer(entity_list_vtable[4]))
    {
        return nullptr;
    }

    auto get_client_entity = reinterpret_cast<get_client_entity_fn>(
        entity_list_vtable[3]);
    auto get_from_handle =
        reinterpret_cast<get_client_entity_from_handle_fn>(
            entity_list_vtable[4]);

    auto* entity = static_cast<std::uint8_t*>(get_client_entity(
        context.entity_list,
        static_cast<int>(entity_index)));
    if (!plausible_pointer(entity))
        return nullptr;

    const std::uint32_t active_weapon_handle =
        *reinterpret_cast<volatile const std::uint32_t*>(
            entity + context.active_weapon_offset);
    if (active_weapon_handle == 0xFFFFFFFFu)
        return nullptr;

    auto* weapon = static_cast<std::uint8_t*>(get_from_handle(
        context.entity_list,
        active_weapon_handle));
    if (!plausible_pointer(weapon))
        return nullptr;

    const std::uint32_t shot_time_bits =
        *reinterpret_cast<volatile const std::uint32_t*>(
            weapon + context.last_shot_time_offset);
    if (!rage_record_logic::positive_finite_float_bits(shot_time_bits))
        return nullptr;

    auto* ring_table = *reinterpret_cast<std::uint8_t* volatile const*>(
        kWindowContext);
    if (!plausible_pointer(ring_table))
        return nullptr;

    const std::uintptr_t table_address =
        reinterpret_cast<std::uintptr_t>(ring_table);
    const std::uintptr_t ring_address = table_address +
        static_cast<std::uintptr_t>(entity_index) * kLagRecordStride;
    if (ring_address < table_address)
        return nullptr;

    auto* ring = reinterpret_cast<std::uint8_t*>(ring_address);
    auto** records = *reinterpret_cast<std::uint8_t** volatile const*>(
        ring + 0x04);
    rage_record_logic::ring_view<std::uint8_t> view{
        records,
        *reinterpret_cast<volatile const std::uint32_t*>(ring + 0x08),
        *reinterpret_cast<volatile const std::uint32_t*>(ring + 0x0C),
        *reinterpret_cast<volatile const std::uint32_t*>(ring + 0x10)
    };

    return rage_record_logic::find_shot_record(
        view,
        shot_time_bits,
        kShotSearchPairs,
        [](const std::uint8_t* record)
        {
            return *reinterpret_cast<volatile const std::uint32_t*>(
                record + kRecordSimulationTimeOffset);
        },
        [validated_candidate](std::uint8_t* record)
        {
            return record == validated_candidate ||
                record_is_usable(record);
        });
}

void* find_entity_shot_record(
    std::uint32_t entity_index,
    void* validated_candidate)
{
    void* selected = nullptr;
    __try
    {
        selected = find_entity_shot_record_unchecked(
            entity_index,
            validated_candidate);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        selected = nullptr;
    }
    return selected;
}
}

extern "C" __declspec(noinline) void* __fastcall
rage_select_preferred_record(void* candidate, void*)
{
    // Candidate access was already native code's responsibility at this site;
    // keep SEH only around the optional external entity/netvar path.
    if (!record_is_usable(candidate))
        return nullptr;

    // Published with InterlockedExchange; the Win32 volatile read keeps the
    // target-selection path free of a locked instruction.
    if (g_shot_context_state != 2)
        return candidate;

    const LONG entity_index = g_selected_entity_index;
    if (entity_index <= 0 ||
        entity_index > static_cast<LONG>(kMaximumPlayerIndex))
    {
        return candidate;
    }

    void* shot_record = find_entity_shot_record(
        static_cast<std::uint32_t>(entity_index),
        candidate);
    return shot_record ? shot_record : candidate;
}

extern "C" __declspec(naked) void rage_capture_record_entity()
{
    __asm
    {
        mov dword ptr [g_selected_entity_index], eax
        cmp eax, 041h
        jb valid_entity

        push 04148F1ACh
        ret

    valid_entity:
        push 04148F1D2h
        ret
    }
}

extern "C" __declspec(noinline) bool __fastcall
rage_preserve_valid_safe(void* record, void*)
{
    return record_expired_strict(record);
}

extern "C" __declspec(noinline) bool __fastcall
rage_preserve_valid_bundle(void* record, void*)
{
    return record_expired_strict(record);
}

extern "C" __declspec(noinline) int __cdecl rage_native_tick_delta(
    std::uint32_t first,
    std::uint32_t second)
{
    const retry_path path = tick_retry_path(
        reinterpret_cast<std::uintptr_t>(_ReturnAddress()));
    const int native_delta =
        reinterpret_cast<tick_delta_fn>(kFnTickDelta)(first, second);
    const bt_score_state state = read_bt_score_state(second);
    const int selected_delta = rage_record_logic::choose_extended_tick_delta(
        static_cast<std::int32_t>(first),
        native_delta,
        state.readable,
        state.classified,
        state.pending,
        kRecordWindowSize);
    if (path != retry_path::none)
    {
        publish_retry_token(
            static_cast<std::int32_t>(first),
            native_delta,
            selected_delta,
            path);
    }
    return selected_delta;
}

extern "C" __declspec(noinline) void* __fastcall
rage_lookup_record_retry(void* context, void*, std::int32_t adjusted_delta)
{
    const retry_path path = lookup_retry_path(
        reinterpret_cast<std::uintptr_t>(_ReturnAddress()));
    const std::uintptr_t token = consume_retry_token();
    auto lookup = reinterpret_cast<record_lookup_fn>(kFnRecordLookup);

    void* record = lookup(context, adjusted_delta);
    if (record)
        return record;

    std::int32_t requested_delta = 0;
    if (!read_retry_token(token, adjusted_delta, path, requested_delta))
        return nullptr;

    void* retry = lookup(context, requested_delta);
    return record_is_usable(retry) ? retry : nullptr;
}

extern "C" __declspec(noinline) bool __fastcall
rage_record_site_window(
    void* context,
    void*,
    std::uint32_t record_tick,
    float tolerance,
    std::uint8_t* valid,
    std::uint32_t reserved_a,
    std::uint32_t reserved_b)
{
    const bool accepted = reinterpret_cast<window_check_fn>(kFnWindowCheck)(
        context,
        record_tick,
        tolerance,
        valid,
        reserved_a,
        reserved_b);
    return accepted;
}

extern "C" __declspec(noinline) bool __fastcall
rage_force_window_true(
    void* context,
    void*,
    std::uint32_t record_tick,
    float tolerance,
    std::uint8_t* valid,
    std::uint32_t reserved_a,
    std::uint32_t reserved_b)
{
    return reinterpret_cast<window_check_fn>(kFnWindowCheck)(
        context,
        record_tick,
        tolerance,
        valid,
        reserved_a,
        reserved_b);
}

extern "C" __declspec(naked) void rage_custom_record_selection()
{
    __asm
    {
        pushfd
        push edx
        push ecx
        push eax
        mov ecx, eax
        xor edx, edx
        call rage_select_preferred_record
        test eax, eax
        jz continue_search

        add esp, 4
        pop ecx
        pop edx
        popfd
        mov esi, eax
        push 04148F2AFh
        ret

    continue_search:
        pop eax
        pop ecx
        pop edx
        popfd
        push 04148F527h
        ret
    }
}

namespace
{
constexpr std::size_t kMaximumPatchSize = 12;

enum site_index : std::size_t
{
    tick_delta_path_1,
    tick_delta_path_2,
    tick_delta_path_3,
    tick_delta_path_4,
    tick_delta_path_5,
    tick_delta_path_6,
    tick_delta_path_7,
    tick_delta_path_8,
    tick_delta_path_9,
    lookup_retry_path_2,
    lookup_retry_path_7,
    lookup_retry_path_8,
    site_count
};

using byte_buffer = std::array<std::uint8_t, kMaximumPatchSize>;

struct patch_site
{
    std::uintptr_t address = 0;
    std::size_t size = 0;
    byte_buffer original{};
    byte_buffer compatible{};
    bool has_compatible = false;
    byte_buffer desired{};
};

std::array<patch_site, site_count> g_sites{};
std::array<patch_code_range, site_count> g_ranges{};
std::array<byte_buffer, site_count> g_previous{};
std::array<bool, site_count> g_changed{};
volatile LONG g_sites_ready = 0;
volatile LONG g_installed = 0;
volatile LONG g_conflicted = 0;
volatile LONG g_transaction_ok = 0;

bool set_bytes(
    byte_buffer& destination,
    std::initializer_list<std::uint8_t> source)
{
    if (source.size() == 0 || source.size() > destination.size())
        return false;

    destination.fill(0);
    std::size_t index = 0;
    for (const std::uint8_t value : source)
        destination[index++] = value;
    return true;
}

bool define_site(
    site_index index,
    std::uintptr_t address,
    std::initializer_list<std::uint8_t> original)
{
    patch_site& site = g_sites[index];
    if (!address || !set_bytes(site.original, original))
        return false;

    site.address = address;
    site.size = original.size();
    site.desired = site.original;
    g_ranges[index] = {address, site.size};
    return true;
}

bool set_compatible(
    site_index index,
    std::initializer_list<std::uint8_t> bytes)
{
    patch_site& site = g_sites[index];
    if (bytes.size() != site.size ||
        !set_bytes(site.compatible, bytes))
    {
        return false;
    }
    site.has_compatible = true;
    return true;
}

bool set_desired(
    site_index index,
    std::initializer_list<std::uint8_t> bytes)
{
    patch_site& site = g_sites[index];
    return bytes.size() == site.size &&
        set_bytes(site.desired, bytes);
}

bool set_relative(
    site_index index,
    std::uint8_t opcode,
    std::uintptr_t destination)
{
    patch_site& site = g_sites[index];
    if (site.size < 5 || !destination)
        return false;

    site.desired.fill(0x90);
    site.desired[0] = opcode;
    const std::uint32_t relative =
        static_cast<std::uint32_t>(destination) -
        static_cast<std::uint32_t>(site.address + 5);
    std::memcpy(
        site.desired.data() + 1,
        &relative,
        sizeof(relative));
    return true;
}

bool set_conditional_relative(
    site_index index,
    std::uint8_t condition_opcode,
    std::uintptr_t destination)
{
    patch_site& site = g_sites[index];
    if (site.size != 6 || !destination)
        return false;

    site.desired.fill(0);
    site.desired[0] = 0x0F;
    site.desired[1] = condition_opcode;
    const std::uint32_t relative =
        static_cast<std::uint32_t>(destination) -
        static_cast<std::uint32_t>(site.address + 6);
    std::memcpy(
        site.desired.data() + 2,
        &relative,
        sizeof(relative));
    return true;
}

bool validate_site_ranges_non_overlapping()
{
    for (std::size_t left = 0; left < g_sites.size(); ++left)
    {
        const patch_site& first = g_sites[left];
        const std::uintptr_t first_end = first.address + first.size;
        if (!first.address || !first.size || first_end < first.address)
            return false;

        for (std::size_t right = left + 1; right < g_sites.size(); ++right)
        {
            const patch_site& second = g_sites[right];
            const std::uintptr_t second_end = second.address + second.size;
            if (!second.address || !second.size ||
                second_end < second.address ||
                (first.address < second_end &&
                    second.address < first_end))
            {
                return false;
            }
        }
    }
    return true;
}

bool initialize_sites()
{
    if (InterlockedCompareExchange(&g_sites_ready, 0, 0) != 0)
        return true;

    bool ok = true;
    ok = ok && define_site(
        tick_delta_path_1,
        0x413F9607,
        {0xE8, 0xD4, 0xAB, 0xF3, 0xFF});
    ok = ok && define_site(
        tick_delta_path_2,
        0x414002A4,
        {0xE8, 0x37, 0x3F, 0xF3, 0xFF});
    ok = ok && define_site(
        tick_delta_path_3,
        0x41478602,
        {0xE8, 0xD9, 0xBB, 0xEB, 0xFF});
    ok = ok && define_site(
        tick_delta_path_4,
        0x4148186F,
        {0xE8, 0x6C, 0x29, 0xEB, 0xFF});
    ok = ok && define_site(
        tick_delta_path_5,
        0x4148475E,
        {0xE8, 0x7D, 0xFA, 0xEA, 0xFF});
    ok = ok && define_site(
        tick_delta_path_6,
        0x4149BBE2,
        {0xE8, 0xF9, 0x85, 0xE9, 0xFF});
    ok = ok && define_site(
        tick_delta_path_7,
        0x4149FA45,
        {0xE8, 0x96, 0x47, 0xE9, 0xFF});
    ok = ok && define_site(
        tick_delta_path_8,
        0x414A8F55,
        {0xE8, 0x86, 0xB2, 0xE8, 0xFF});
    ok = ok && define_site(
        tick_delta_path_9,
        0x414BA7F9,
        {0xE8, 0xE2, 0x99, 0xE7, 0xFF});
    ok = ok && define_site(
        lookup_retry_path_2,
        0x414002B8,
        {0xE8, 0x23, 0xEE, 0xF5, 0xFF});
    ok = ok && define_site(
        lookup_retry_path_7,
        0x4149FA50,
        {0xE8, 0x8B, 0xF6, 0xEB, 0xFF});
    ok = ok && define_site(
        lookup_retry_path_8,
        0x414A8F69,
        {0xE8, 0x72, 0x61, 0xEB, 0xFF});

    ok = ok && validate_site_ranges_non_overlapping();

    for (std::size_t index = tick_delta_path_1;
         index <= tick_delta_path_9;
         ++index)
    {
        ok = ok && set_relative(
            static_cast<site_index>(index),
            0xE8,
            reinterpret_cast<std::uintptr_t>(&rage_native_tick_delta));
    }
    for (std::size_t index = lookup_retry_path_2;
         index <= lookup_retry_path_8;
         ++index)
    {
        ok = ok && set_relative(
            static_cast<site_index>(index),
            0xE8,
            reinterpret_cast<std::uintptr_t>(&rage_lookup_record_retry));
    }

    if (!ok)
        return false;

    InterlockedExchange(&g_sites_ready, 1);
    return true;
}

bool query_image_range(std::uintptr_t address, std::size_t size)
{
    if (!address || !size)
        return false;

    MEMORY_BASIC_INFORMATION information{};
    if (VirtualQuery(
            reinterpret_cast<const void*>(address),
            &information,
            sizeof(information)) != sizeof(information))
    {
        return false;
    }

    if (information.State != MEM_COMMIT ||
        (information.Protect & PAGE_GUARD) != 0 ||
        (information.Protect & 0xFF) == PAGE_NOACCESS ||
        information.AllocationBase !=
            reinterpret_cast<void*>(kBuildBase))
    {
        return false;
    }

    const std::uintptr_t region_begin =
        reinterpret_cast<std::uintptr_t>(information.BaseAddress);
    const std::uintptr_t region_end =
        region_begin + information.RegionSize;
    const std::uintptr_t range_end = address + size;
    return region_end >= region_begin &&
        range_end >= address &&
        address >= region_begin &&
        range_end <= region_end;
}

bool validate_dependencies()
{
    struct dependency
    {
        std::uintptr_t address;
        std::size_t size;
    };

    constexpr dependency dependencies[] = {
        {kFnRecordExpired, 1},
        {kFnTickDelta, 1},
        {kFnRecordLookup, 1},
        {kBtScoreLookup, sizeof(void*)},
    };

    for (const dependency& item : dependencies)
    {
        if (!query_image_range(item.address, item.size))
            return false;
    }
    return true;
}

bool read_site(const patch_site& site, byte_buffer& output)
{
    // Every site is range-validated before installation. Keep the watchdog
    // read fail-safe with SEH without repeating VirtualQuery per site.
    if (!site.address || !site.size || site.size > output.size())
        return false;

    __try
    {
        std::memcpy(
            output.data(),
            reinterpret_cast<const void*>(site.address),
            site.size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    return true;
}

bool bytes_equal(
    const byte_buffer& left,
    const byte_buffer& right,
    std::size_t size)
{
    for (std::size_t index = 0; index < size; ++index)
    {
        if (left[index] != right[index])
            return false;
    }
    return true;
}

bool is_known_state(
    const patch_site& site,
    const byte_buffer& current)
{
    return bytes_equal(current, site.desired, site.size) ||
        bytes_equal(current, site.original, site.size) ||
        (site.has_compatible &&
            bytes_equal(current, site.compatible, site.size));
}

bool write_site(
    const patch_site& site,
    const byte_buffer& bytes)
{
    DWORD old_protection = 0;
    if (!VirtualProtect(
            reinterpret_cast<void*>(site.address),
            site.size,
            PAGE_EXECUTE_READWRITE,
            &old_protection))
    {
        return false;
    }

    bool copied = false;
    __try
    {
        std::memcpy(
            reinterpret_cast<void*>(site.address),
            bytes.data(),
            site.size);
        copied = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        copied = false;
    }

    DWORD ignored = 0;
    const bool restored = VirtualProtect(
        reinterpret_cast<void*>(site.address),
        site.size,
        old_protection,
        &ignored) != FALSE;
    const bool flushed = FlushInstructionCache(
        GetCurrentProcess(),
        reinterpret_cast<const void*>(site.address),
        site.size) != FALSE;

    byte_buffer current{};
    return copied &&
        restored &&
        flushed &&
        read_site(site, current) &&
        bytes_equal(current, bytes, site.size);
}

void rollback_transaction(std::size_t attempted)
{
    for (std::size_t index = attempted; index > 0; --index)
    {
        const std::size_t site_number = index - 1;
        if (g_changed[site_number])
        {
            write_site(
                g_sites[site_number],
                g_previous[site_number]);
        }
    }
}

void patch_transaction_writer()
{
    InterlockedExchange(&g_transaction_ok, 0);
    g_changed.fill(false);

    for (std::size_t index = 0; index < g_sites.size(); ++index)
    {
        if (!read_site(g_sites[index], g_previous[index]) ||
            !is_known_state(g_sites[index], g_previous[index]))
        {
            return;
        }
    }

    for (std::size_t index = 0; index < g_sites.size(); ++index)
    {
        const patch_site& site = g_sites[index];
        if (bytes_equal(
                g_previous[index],
                site.desired,
                site.size))
        {
            continue;
        }

        g_changed[index] = true;
        if (!write_site(site, site.desired))
        {
            rollback_transaction(index + 1);
            return;
        }
    }

    InterlockedExchange(&g_transaction_ok, 1);
}

bool validate_all_sites(bool* needs_write)
{
    bool pending = false;
    for (const patch_site& site : g_sites)
    {
        byte_buffer current{};
        if (!read_site(site, current) ||
            !is_known_state(site, current))
        {
            return false;
        }

        if (!bytes_equal(current, site.desired, site.size))
            pending = true;
    }

    if (needs_write)
        *needs_write = pending;
    return true;
}

bool run_patch_transaction_locked()
{
    InterlockedExchange(&g_transaction_ok, 0);
    if (!run_persist_patch_transaction_locked(
            g_ranges.data(),
            g_ranges.size(),
            patch_transaction_writer))
    {
        return false;
    }

    return InterlockedCompareExchange(
        &g_transaction_ok,
        0,
        0) != 0;
}

void persist_rage_record_patches()
{
    if (InterlockedCompareExchange(&g_installed, 0, 0) == 0 ||
        InterlockedCompareExchange(&g_conflicted, 0, 0) != 0)
    {
        return;
    }

    bool needs_write = false;
    if (!validate_all_sites(&needs_write))
    {
        InterlockedExchange(&g_conflicted, 1);
        return;
    }
    if (!needs_write)
        return;

    if (!run_patch_transaction_locked())
        InterlockedExchange(&g_conflicted, 1);
}
}

bool apply_rage_record_patches()
{
    if (!initialize_sites() ||
        !validate_dependencies() ||
        !ensure_tick_delta_tls())
        return false;

    bool needs_write = false;
    if (!validate_all_sites(&needs_write))
        return false;

    bool applied = true;
    if (needs_write)
    {
        acquire_patch_write_lock();
        applied = run_patch_transaction_locked();
        release_patch_write_lock();
    }
    if (!applied)
        return false;

    InterlockedExchange(&g_installed, 1);
    register_persist_callback(persist_rage_record_patches);
    return true;
}
