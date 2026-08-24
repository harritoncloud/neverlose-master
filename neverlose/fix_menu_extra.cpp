// ============================================================
//  fix_menu_extra.cpp
//
//  Native C++ port of 16_menu changer.lua ("Extra" tab).
//  Branding, about panel, profile section, chat widget,
//  and URL redirect patches.
//  Persist via unified watchdog (check-before-write).
//
//  ---- HOW TO CUSTOMIZE ----
//  Edit the CFG_ constants below to change branding text,
//  toggle features on/off, etc.
// ============================================================

#include "neverlose.h"
#include <array>
#include <cstdint>
#include <cstring>

#include "fix_menu_extra.h"
#include "fix_persist.h"

// ============================================================
//  CONFIGURATION — edit these to customise your build
// ============================================================

// Branding text (max 16 chars for watermark, 12 for about)
static const char CFG_WATERMARK[]  = "patchwin.cc";
static const char CFG_ABOUT_LOGO[] = "patchwin.cc";

// About-panel text overrides
static const char CFG_BRANCH[]  = "";
static const char CFG_UPDATED[] = "";
static const char CFG_VALID[]   = "";

// Profile section overrides
static const char CFG_TILL_LABEL[] = "Expires";
static const char CFG_TILL_VALUE[] = "Never";

// Feature toggles
static constexpr bool  CFG_SHOW_ABOUT    = true;   // true = show w/ text overrides, false = NOP-out
static constexpr bool  CFG_SHOW_PROFILE  = true;   // true = show w/ text overrides, false = NOP-out
static constexpr bool  CFG_HIDE_CHAT     = false;  // true = hide sidebar chat widget
static constexpr bool  CFG_REDIRECT_URLS = false;  // true = redirect market/docs links
static constexpr float CFG_PROFILE_OFFSET = -25.0f;// spacing tweak (only if profile hidden)

// URL redirect targets (only used when CFG_REDIRECT_URLS == true)
static const char CFG_URL_CONFIGS[] = "https://gamesense.pub/forums/viewforum.php?id=11";
static const char CFG_URL_SCRIPTS[] = "https://gamesense.pub/forums/viewforum.php?id=11";
static const char CFG_URL_DOCS[]    = "https://gamesense.pub/forums/lua.php";

// ============================================================
//  Patch addresses & XOR keys
// ============================================================

// About logo
static constexpr uintptr_t ABOUT_ADDRS[] = { 0x4151B301, 0x4151B2FA, 0x4151B31B };
static constexpr uint32_t  ABOUT_KEYS[]  = { 0x4EE22AB1, 0x2DB6684B, 0xF8009786 };

// Profile padding floats
static constexpr uintptr_t PROF_PAD_ADDRS[] = { 0x420A4800, 0x420A4804 };

// Code-cave target functions
static constexpr uintptr_t ABOUT_TEXT_FN    = 0x41CA67C0;
static constexpr uintptr_t TILL_LABEL_FN    = 0x41CA67C0;
static constexpr uintptr_t TILL_VALUE_FN    = 0x41CBCDF0;

// ============================================================
//  NOP-patch tables  (addr, original bytes, size)
// ============================================================

struct NopPatch { uintptr_t addr; const uint8_t* orig; size_t len; bool applied; };

// --- about panel originals ---
static const uint8_t A0[] ={0xE8,0x0D,0x4D,0x79,0x00};
static const uint8_t A1[] ={0xF3,0x0F,0x58,0x86,0x9C,0x00,0x00,0x00};
static const uint8_t A2[] ={0xF3,0x0F,0x58,0x86,0x98,0x00,0x00,0x00};
static const uint8_t A3[] ={0xE8,0xF0,0xBA,0x77,0x00};
static const uint8_t A4[] ={0xE8,0xDD,0xB2,0x78,0x00};
static const uint8_t A5[] ={0xE8,0x80,0xB2,0x78,0x00};
static const uint8_t A6[] ={0xE8,0xDF,0xC7,0x74,0x00};
static const uint8_t A7[] ={0xE8,0x23,0xB1,0x78,0x00};
static const uint8_t A8[] ={0xE8,0xC9,0xB0,0x78,0x00};
static const uint8_t A9[] ={0xE8,0x25,0xC6,0x74,0x00};
static const uint8_t A10[]={0xE8,0x01,0xAF,0x78,0x00};
static const uint8_t A11[]={0xE8,0xA6,0xAE,0x78,0x00};
static const uint8_t A12[]={0xE8,0x03,0xC4,0x74,0x00};
static const uint8_t A13[]={0xE8,0x6C,0xAD,0x78,0x00};
static const uint8_t A14[]={0xE8,0x0F,0xAD,0x78,0x00};
static const uint8_t A15[]={0xE8,0x6E,0xC2,0x74,0x00};
static const uint8_t A16[]={0xF3,0x0F,0x10,0x46,0x2C,0xF3,0x0F,0x5C,0x46,0x60,
                            0xF3,0x0F,0x59,0x05,0x18,0xA5,0x05,0x42};
static const uint8_t A17[]={0xE8,0x4C,0xAA,0x78,0x00};
static const uint8_t A18[]={0xE8,0xF6,0xB0,0x77,0x00};

static NopPatch g_about_nops[] = {
    {0x4151B37E,A0, 5,false},{0x4151B3A1,A1, 8,false},{0x4151B3D3,A2, 8,false},
    {0x4151B3BB,A3, 5,false},{0x4151B4DE,A4, 5,false},{0x4151B53B,A5, 5,false},
    {0x4151B50C,A6, 5,false},{0x4151B698,A7, 5,false},{0x4151B6F2,A8, 5,false},
    {0x4151B6C6,A9, 5,false},{0x4151B8BA,A10,5,false},{0x4151B915,A11,5,false},
    {0x4151B8E8,A12,5,false},{0x4151BA4F,A13,5,false},{0x4151BAAC,A14,5,false},
    {0x4151BA7D,A15,5,false},{0x4151BD3E,A16,18,false},{0x4151BD6F,A17,5,false},
    {0x4151BDB5,A18,5,false},
};
static constexpr int ABOUT_NOP_COUNT = sizeof(g_about_nops)/sizeof(g_about_nops[0]);

// --- profile panel originals ---
static const uint8_t P0[]={0xE8,0xDE,0x02,0x69,0x00};
static const uint8_t P1[]={0xF3,0x0F,0x5C,0xC1};
static const uint8_t P2[]={0xE8,0xAF,0x5E,0x6B,0x00};
static const uint8_t P3[]={0xE8,0xB3,0x3D,0x6A,0x00};
static const uint8_t P4[]={0xE8,0xD5,0xF9,0x69,0x00};
static const uint8_t P5[]={0xE8,0x3F,0xF9,0x69,0x00};

static NopPatch g_profile_nops[] = {
    {0x41606BCD,P0,5,false},{0x41605B77,P1,4,false},{0x41606F3C,P2,5,false},
    {0x41606D28,P3,5,false},{0x41606DE6,P4,5,false},{0x41606E7C,P5,5,false},
};
static constexpr int PROFILE_NOP_COUNT = sizeof(g_profile_nops)/sizeof(g_profile_nops[0]);

// ============================================================
//  Code-cave site descriptors
// ============================================================

struct TextSite { uintptr_t addr; uint8_t orig[5]; uint8_t arg_off; };
struct UrlSite  { uintptr_t addr; uintptr_t ret; size_t size; uint8_t orig[20]; };

static const TextSite g_about_sites[] = {
    { 0x4151B6F2, {0xE8,0xC9,0xB0,0x78,0x00}, 0x08 },
    { 0x4151B915, {0xE8,0xA6,0xAE,0x78,0x00}, 0x08 },
    { 0x4151BAAC, {0xE8,0x0F,0xAD,0x78,0x00}, 0x08 },
};

struct TillSite { uintptr_t addr; uint8_t orig[5]; uintptr_t target; uint8_t arg_off; };

static const TillSite g_till_sites[] = {
    { 0x41606E7C, {0xE8,0x3F,0xF9,0x69,0x00}, TILL_LABEL_FN, 0x08 },
    { 0x41606F3C, {0xE8,0xAF,0x5E,0x6B,0x00}, TILL_VALUE_FN, 0x08 },
};

static const UrlSite g_url_sites[] = {
    { 0x415395BD, 0x415395CE, 17,
      {0x6A,0x05,0x6A,0x00,0x6A,0x00,0x53,0x6A,0x00,0x6A,0x00,0xFF,0x15,0xD8,0x8F,0x1B,0x42} },
    { 0x41B5EC30, 0x41B5EC44, 20,
      {0x6A,0x05,0x6A,0x00,0x6A,0x00,0x8D,0x46,0x40,0x50,0x6A,0x00,0x6A,0x00,0xFF,0x15,0xD8,0x8F,0x1B,0x42} },
    { 0x41B5EE67, 0x41B5EE7B, 20,
      {0x6A,0x05,0x6A,0x00,0x6A,0x00,0x8D,0x46,0x40,0x50,0x6A,0x00,0x6A,0x00,0xFF,0x15,0xD8,0x8F,0x1B,0x42} },
};

// ============================================================
//  Runtime state
// ============================================================
static struct {
    float    orig_floats[2];          // saved profile-padding floats
    uint32_t about_sentinel;          // cached expected val at ABOUT_ADDRS[0]
    uint32_t wm_sentinel;             // cached expected val at 0x41516808
    void*    about_block;             // VirtualAlloc block for about-text caves
    void*    till_block;              // VirtualAlloc block for till caves
    void*    url_block;               // VirtualAlloc block for URL caves
    void*    chat_caves[3];           // chat hider code caves
    bool     about_installed;
    bool     till_installed;
    bool     url_installed;
    bool     chat_installed;
} g_ex = {};

// ============================================================
//  Low-level memory helpers
// ============================================================

static void mem_write(uintptr_t addr, const void* data, size_t sz)
{
    if (!data || !sz)
        return;

    const auto* expected = static_cast<const uint8_t*>(data);
    const auto* current = reinterpret_cast<volatile const uint8_t*>(addr);
    bool matches = true;
    for (size_t i = 0; i < sz; ++i)
    {
        if (current[i] != expected[i])
        {
            matches = false;
            break;
        }
    }
    if (matches)
        return;

    PVOID  base = reinterpret_cast<PVOID>(addr);
    SIZE_T len  = sz;
    DWORD  old  = 0;
    if (!NT_SUCCESS(NtProtectVirtualMemory(
        NtCurrentProcess(), &base, &len, PAGE_EXECUTE_READWRITE, &old)))
    {
        return;
    }

    memcpy(reinterpret_cast<void*>(addr), data, sz);

    PVOID restore_base = reinterpret_cast<PVOID>(addr);
    SIZE_T restore_len = sz;
    DWORD ignored = 0;
    NtProtectVirtualMemory(
        NtCurrentProcess(), &restore_base, &restore_len, old, &ignored);
    NtFlushInstructionCache(NtCurrentProcess(), reinterpret_cast<PVOID>(addr), sz);
}

static void mem_write_u32(uintptr_t addr, uint32_t v)  { mem_write(addr, &v, 4); }
static void mem_write_f32(uintptr_t addr, float v)     { mem_write(addr, &v, 4); }
static uint32_t mem_read_u32(uintptr_t addr)            { return *reinterpret_cast<volatile uint32_t*>(addr); }
static float    mem_read_f32(uintptr_t addr)            { return *reinterpret_cast<volatile float*>(addr); }

static void mem_nop(uintptr_t addr, size_t sz)
{
    const auto* current = reinterpret_cast<volatile const uint8_t*>(addr);
    bool already_nopped = true;
    for (size_t i = 0; i < sz; ++i)
    {
        if (current[i] != 0x90)
        {
            already_nopped = false;
            break;
        }
    }
    if (already_nopped)
        return;

    PVOID  base = reinterpret_cast<PVOID>(addr);
    SIZE_T len  = sz;
    DWORD  old  = 0;
    if (!NT_SUCCESS(NtProtectVirtualMemory(
        NtCurrentProcess(), &base, &len, PAGE_EXECUTE_READWRITE, &old)))
    {
        return;
    }

    memset(reinterpret_cast<void*>(addr), 0x90, sz);

    PVOID restore_base = reinterpret_cast<PVOID>(addr);
    SIZE_T restore_len = sz;
    DWORD ignored = 0;
    NtProtectVirtualMemory(
        NtCurrentProcess(), &restore_base, &restore_len, old, &ignored);
    NtFlushInstructionCache(NtCurrentProcess(), reinterpret_cast<PVOID>(addr), sz);
}

static bool mem_cmp(uintptr_t addr, const uint8_t* expected, size_t sz)
{
    auto* p = reinterpret_cast<volatile uint8_t*>(addr);
    for (size_t i = 0; i < sz; i++)
        if (p[i] != expected[i]) return false;
    return true;
}

static void* cave_alloc(size_t sz)
{
    return VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

static void cave_free(void*& p)
{
    if (p) { VirtualFree(p, 0, MEM_RELEASE); p = nullptr; }
}

static void cave_seal(void* p, size_t sz)
{
    if (!p || !sz)
        return;

    DWORD old = 0;
    if (VirtualProtect(p, sz, PAGE_EXECUTE_READ, &old))
        FlushInstructionCache(GetCurrentProcess(), p, sz);
}

static void write_cstr(uintptr_t addr, const char* s, size_t max)
{
    auto* p = reinterpret_cast<uint8_t*>(addr);
    memset(p, 0, max);
    size_t n = strlen(s);
    if (n > max - 1) n = max - 1;
    memcpy(p, s, n);
}

// ============================================================
//  JMP / CALL encoding
// ============================================================

static void encode_jmp(uint8_t* buf, uintptr_t from, uintptr_t to, size_t patch_sz)
{
    buf[0] = 0xE9;
    *reinterpret_cast<uint32_t*>(buf + 1) = static_cast<uint32_t>(to - (from + 5));
    for (size_t i = 5; i < patch_sz; i++) buf[i] = 0x90;
}

static void encode_call(uint8_t* buf, uintptr_t from, uintptr_t to)
{
    buf[0] = 0xE8;
    *reinterpret_cast<uint32_t*>(buf + 1) = static_cast<uint32_t>(to - (from + 5));
}

// ============================================================
//  Branding — XOR-encoded string writes
// ============================================================

static uint32_t pack4(const char* text, int off)
{
    uint8_t b[4] = {};
    size_t  len  = strlen(text);
    for (int i = 0; i < 4 && (off + i) < (int)len; i++)
        b[i] = static_cast<uint8_t>(text[off + i]);
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
}

static void set_about_logo(const char* text)
{
    char pad[12]; memset(pad, ' ', 12);
    size_t n = strlen(text); if (n > 12) n = 12;
    memcpy(pad, text, n);
    mem_write_u32(ABOUT_ADDRS[0], pack4(pad, 0) ^ ABOUT_KEYS[0]);
    mem_write_u32(ABOUT_ADDRS[1], pack4(pad, 4) ^ ABOUT_KEYS[1]);
    mem_write_u32(ABOUT_ADDRS[2], pack4(pad, 8) ^ ABOUT_KEYS[2]);
    g_ex.about_sentinel = mem_read_u32(ABOUT_ADDRS[0]);
}

static void set_watermark(const char* text)
{
    uint32_t dw[4] = {};
    size_t n = strlen(text); if (n > 16) n = 16;
    memcpy(dw, text, n);

    uint32_t ep1 = dw[0] ^ 0x4EE22AB1;
    uint32_t ep2 = dw[1] ^ 0x2DB6684B;
    uint32_t ep3 = dw[2] ^ 0xF8009786;
    uint32_t ep4 = dw[3] ^ 0x3BFABFB6;

    mem_write_u32(0x41516C36, 0x3BFABFB6);
    mem_write_u32(0x41516C3D, 0xF8009786);
    mem_write_u32(0x41516808, ep1 - 0x4EE22AB1);
    mem_write_u32(0x4151681E, ep2);
    mem_write_u32(0x41516BEB, ep2);
    mem_write_u32(0x41516850, ep3);
    mem_write_u32(0x41516C2A, ep3);
    mem_write_u32(0x41516845, ep4);
    mem_write_u32(0x41516C1E, ep4);
    mem_write_u32(0x4151E6E2, ep1 - 0x3C4E);
    mem_write_u32(0x4151E6F3, ep2);
    mem_write_u32(0x4151E713, ep3);
    mem_write_u32(0x4151E70B, ep4);

    g_ex.wm_sentinel = mem_read_u32(0x41516808);
}

// ============================================================
//  NOP-patch group helpers
// ============================================================

static void nop_apply(NopPatch* p, int count)
{
    for (int i = 0; i < count; i++)
    {
        if (!p[i].applied && mem_cmp(p[i].addr, p[i].orig, p[i].len))
        {
            mem_nop(p[i].addr, p[i].len);
            p[i].applied = true;
        }
    }
}

static void nop_restore(NopPatch* p, int count)
{
    for (int i = 0; i < count; i++)
    {
        if (p[i].applied)
        {
            mem_write(p[i].addr, p[i].orig, p[i].len);
            p[i].applied = false;
        }
    }
}

// ============================================================
//  About-text overrides (code caves)
// ============================================================

static void install_about_text(const char* branch, const char* updated, const char* valid)
{
    cave_free(g_ex.about_block);
    g_ex.about_installed = false;

    void* blk = cave_alloc(0x3000);
    if (!blk) return;
    g_ex.about_block = blk;

    auto base = reinterpret_cast<uintptr_t>(blk);
    uintptr_t caves[]   = { base, base + 0x100, base + 0x200 };
    uintptr_t strings[] = { base + 0x1000, base + 0x1400, base + 0x1800 };

    const char* texts[] = { branch, updated, valid };
    for (int i = 0; i < 3; i++)
        write_cstr(strings[i], texts[i], 0x300);

    for (int i = 0; i < 3; i++)
    {
        // mov dword [esp+arg], string; jmp target_fn   (13 bytes)
        uint8_t cave[13] = { 0xC7, 0x44, 0x24, g_about_sites[i].arg_off };
        *reinterpret_cast<uint32_t*>(cave + 4) = static_cast<uint32_t>(strings[i]);
        cave[8] = 0xE9;
        *reinterpret_cast<uint32_t*>(cave + 9) = static_cast<uint32_t>(ABOUT_TEXT_FN - (caves[i] + 13));
        memcpy(reinterpret_cast<void*>(caves[i]), cave, 13);

        uint8_t call[5];
        encode_call(call, g_about_sites[i].addr, caves[i]);
        mem_write(g_about_sites[i].addr, call, 5);
    }
    cave_seal(blk, 0x3000);
    g_ex.about_installed = true;
}

static void restore_about_text()
{
    if (!g_ex.about_installed) return;
    for (int i = 0; i < 3; i++)
        mem_write(g_about_sites[i].addr, g_about_sites[i].orig, 5);
    cave_free(g_ex.about_block);
    g_ex.about_installed = false;
}

// ============================================================
//  Profile-till overrides (code caves)
// ============================================================

static void install_till(const char* label, const char* value)
{
    cave_free(g_ex.till_block);
    g_ex.till_installed = false;

    void* blk = cave_alloc(0x3000);
    if (!blk) return;
    g_ex.till_block = blk;

    auto base = reinterpret_cast<uintptr_t>(blk);
    uintptr_t caves[]   = { base, base + 0x100 };
    uintptr_t strings[] = { base + 0x1000, base + 0x1400 };

    write_cstr(strings[0], label, 0x300);
    write_cstr(strings[1], value, 0x300);

    for (int i = 0; i < 2; i++)
    {
        uint8_t cave[13] = { 0xC7, 0x44, 0x24, g_till_sites[i].arg_off };
        *reinterpret_cast<uint32_t*>(cave + 4) = static_cast<uint32_t>(strings[i]);
        cave[8] = 0xE9;
        *reinterpret_cast<uint32_t*>(cave + 9) = static_cast<uint32_t>(g_till_sites[i].target - (caves[i] + 13));
        memcpy(reinterpret_cast<void*>(caves[i]), cave, 13);

        uint8_t call[5];
        encode_call(call, g_till_sites[i].addr, caves[i]);
        mem_write(g_till_sites[i].addr, call, 5);
    }
    cave_seal(blk, 0x3000);
    g_ex.till_installed = true;
}

static void restore_till()
{
    if (!g_ex.till_installed) return;
    for (int i = 0; i < 2; i++)
        mem_write(g_till_sites[i].addr, g_till_sites[i].orig, 5);
    cave_free(g_ex.till_block);
    g_ex.till_installed = false;
}

// ============================================================
//  URL redirects (code caves → ShellExecuteA)
// ============================================================

static void install_url_redirects(const char* configs, const char* scripts, const char* docs)
{
    cave_free(g_ex.url_block);
    g_ex.url_installed = false;

    void* blk = cave_alloc(0x4000);
    if (!blk) return;
    g_ex.url_block = blk;

    auto base = reinterpret_cast<uintptr_t>(blk);
    uintptr_t caves[]   = { base, base + 0x100, base + 0x200 };
    uintptr_t strings[] = { base + 0x1000, base + 0x1800, base + 0x2000 };

    write_cstr(strings[0], configs, 0x700);
    write_cstr(strings[1], docs,    0x700);
    write_cstr(strings[2], scripts, 0x700);

    for (int i = 0; i < 3; i++)
    {
        // push 5; push 0; push 0; push str; push 0; push 0; call [IAT]; jmp ret
        uint8_t cave[26] = {
            0x6A,0x05, 0x6A,0x00, 0x6A,0x00,
            0x68, 0,0,0,0,                        // push string
            0x6A,0x00, 0x6A,0x00,
            0xFF,0x15, 0xD8,0x8F,0x1B,0x42,       // call [ShellExecuteA IAT]
            0xE9, 0,0,0,0                          // jmp ret
        };
        *reinterpret_cast<uint32_t*>(cave + 7)  = static_cast<uint32_t>(strings[i]);
        *reinterpret_cast<uint32_t*>(cave + 22) = static_cast<uint32_t>(g_url_sites[i].ret - (caves[i] + 26));
        memcpy(reinterpret_cast<void*>(caves[i]), cave, 26);

        uint8_t jmp[20];
        encode_jmp(jmp, g_url_sites[i].addr, caves[i], g_url_sites[i].size);
        mem_write(g_url_sites[i].addr, jmp, g_url_sites[i].size);
    }
    cave_seal(blk, 0x4000);
    g_ex.url_installed = true;
}

static void restore_url_redirects()
{
    if (!g_ex.url_installed) return;
    for (int i = 0; i < 3; i++)
        mem_write(g_url_sites[i].addr, g_url_sites[i].orig, g_url_sites[i].size);
    cave_free(g_ex.url_block);
    g_ex.url_installed = false;
}

// ============================================================
//  Chat-widget hider (code caves)
// ============================================================

// Original bytes at the five patch sites
static const uint8_t CH0[] = {0xA1,0x10,0x47,0x4B,0x42};
static const uint8_t CH1[] = {0x80,0xB0,0xE0,0x10,0x00,0x00,0x01};
static const uint8_t CH2[] = {0xE8,0x29,0x3A,0x6A,0x00};
static const uint8_t CH3[] = {0xE8,0x8F,0x79,0xF9,0xFF};
static const uint8_t CH4[] = {0xE8,0x0E,0xF6,0xF9,0xFF};

static void install_chat_hider()
{
    if (g_ex.chat_installed) return;

    void* c0 = cave_alloc(256);
    void* c1 = cave_alloc(256);
    void* c2 = cave_alloc(256);
    if (!c0 || !c1 || !c2)
    {
        if (c0) VirtualFree(c0, 0, MEM_RELEASE);
        if (c1) VirtualFree(c1, 0, MEM_RELEASE);
        if (c2) VirtualFree(c2, 0, MEM_RELEASE);
        return;
    }
    g_ex.chat_caves[0] = c0;
    g_ex.chat_caves[1] = c1;
    g_ex.chat_caves[2] = c2;

    auto cc = reinterpret_cast<uintptr_t>(c0);
    auto cg = reinterpret_cast<uintptr_t>(c1);
    auto cm = reinterpret_cast<uintptr_t>(c2);

    // Cave 0: mov eax,[0x424B4710]; mov byte [eax+0x10E0],0; jmp back
    {
        uint8_t b[17] = {
            0xA1,0x10,0x47,0x4B,0x42,
            0xC6,0x80,0xE0,0x10,0x00,0x00,0x00,
            0xE9,0x00,0x00,0x00,0x00
        };
        *reinterpret_cast<uint32_t*>(b+13) = static_cast<uint32_t>(0x41607EF2 - (cc+17));
        memcpy(c0, b, 17);
    }
    // Cave 1: cmp [esp+8],0x42176AFA; je skip; call fn; jmp back; xor eax,eax; jmp back
    {
        uint8_t b[27] = {
            0x81,0x7C,0x24,0x08,0xFA,0x6A,0x17,0x42,
            0x74,0x0A,
            0xE8,0x00,0x00,0x00,0x00,
            0xE9,0x00,0x00,0x00,0x00,
            0x31,0xC0,
            0xE9,0x00,0x00,0x00,0x00
        };
        *reinterpret_cast<uint32_t*>(b+11) = static_cast<uint32_t>(0x41C637E0 - (cg+15));
        *reinterpret_cast<uint32_t*>(b+16) = static_cast<uint32_t>(0x41CC41D2 - (cg+20));
        *reinterpret_cast<uint32_t*>(b+23) = static_cast<uint32_t>(0x41CC41D2 - (cg+27));
        memcpy(c1, b, 27);
    }
    // Cave 2: cmp [ebp+8],0x42176AFA; je skip; call fn; jmp back; xor eax,eax; jmp back
    {
        uint8_t b[26] = {
            0x81,0x7D,0x08,0xFA,0x6A,0x17,0x42,
            0x74,0x0A,
            0xE8,0x00,0x00,0x00,0x00,
            0xE9,0x00,0x00,0x00,0x00,
            0x31,0xC0,
            0xE9,0x00,0x00,0x00,0x00
        };
        *reinterpret_cast<uint32_t*>(b+10) = static_cast<uint32_t>(0x41C5B9A0 - (cm+14));
        *reinterpret_cast<uint32_t*>(b+15) = static_cast<uint32_t>(0x41CC4011 - (cm+19));
        *reinterpret_cast<uint32_t*>(b+22) = static_cast<uint32_t>(0x41CC4011 - (cm+26));
        memcpy(c2, b, 26);
    }

    cave_seal(c0, 256);
    cave_seal(c1, 256);
    cave_seal(c2, 256);

    // Patch original sites
    uint8_t jbuf[20];
    encode_jmp(jbuf, 0x41607EED, cc, 5);   mem_write(0x41607EED, jbuf, 5);
    mem_nop(0x41607F22, 7);
    { uint8_t b[5]={0x31,0xC0,0x90,0x90,0x90}; mem_write(0x41607F72, b, 5); }
    encode_jmp(jbuf, 0x41CC400C, cm, 5);   mem_write(0x41CC400C, jbuf, 5);
    encode_jmp(jbuf, 0x41CC41CD, cg, 5);   mem_write(0x41CC41CD, jbuf, 5);

    g_ex.chat_installed = true;
}

static void restore_chat_hider()
{
    if (!g_ex.chat_installed) return;
    mem_write(0x41607EED, CH0, 5);
    mem_write(0x41607F22, CH1, 7);
    mem_write(0x41607F72, CH2, 5);
    mem_write(0x41CC400C, CH3, 5);
    mem_write(0x41CC41CD, CH4, 5);
    for (auto& p : g_ex.chat_caves) cave_free(p);
    g_ex.chat_installed = false;
}

// ============================================================
//  Profile-padding helpers
// ============================================================

static void save_profile_floats()
{
    for (int i = 0; i < 2; i++)
        g_ex.orig_floats[i] = mem_read_f32(PROF_PAD_ADDRS[i]);
}

static void apply_profile_offset(float off)
{
    for (int i = 0; i < 2; i++)
        mem_write_f32(PROF_PAD_ADDRS[i], g_ex.orig_floats[i] + off);
}

static void restore_profile_floats()
{
    for (int i = 0; i < 2; i++)
        mem_write_f32(PROF_PAD_ADDRS[i], g_ex.orig_floats[i]);
}

// ============================================================
//  Persist callback — check-before-write, runs every 16 ms
// ============================================================

static bool extra_needs_repair()
{
    if (mem_read_u32(ABOUT_ADDRS[0]) != g_ex.about_sentinel ||
        mem_read_u32(0x41516808) != g_ex.wm_sentinel)
    {
        return true;
    }

    if (CFG_SHOW_ABOUT && g_ex.about_installed && g_ex.about_block)
    {
        for (int i = 0; i < 3; i++)
        {
            if (mem_cmp(g_about_sites[i].addr, g_about_sites[i].orig, 5))
                return true;
        }
    }

    if (CFG_SHOW_PROFILE && g_ex.till_installed && g_ex.till_block)
    {
        for (int i = 0; i < 2; i++)
        {
            if (mem_cmp(g_till_sites[i].addr, g_till_sites[i].orig, 5))
                return true;
        }
    }

    if (!CFG_SHOW_ABOUT)
    {
        for (int i = 0; i < ABOUT_NOP_COUNT; i++)
        {
            if (mem_cmp(g_about_nops[i].addr, g_about_nops[i].orig, g_about_nops[i].len))
                return true;
        }
    }

    if (!CFG_SHOW_PROFILE)
    {
        for (int i = 0; i < PROFILE_NOP_COUNT; i++)
        {
            if (mem_cmp(g_profile_nops[i].addr, g_profile_nops[i].orig, g_profile_nops[i].len))
                return true;
        }
    }

    return false;
}

static void extra_apply_repairs()
{
    // --- branding (sentinel check) ---
    if (mem_read_u32(ABOUT_ADDRS[0]) != g_ex.about_sentinel) set_about_logo(CFG_ABOUT_LOGO);
    if (mem_read_u32(0x41516808)     != g_ex.wm_sentinel)    set_watermark(CFG_WATERMARK);

    // --- about text caves ---
    if (CFG_SHOW_ABOUT && g_ex.about_installed && g_ex.about_block)
    {
        auto base = reinterpret_cast<uintptr_t>(g_ex.about_block);
        for (int i = 0; i < 3; i++)
        {
            if (mem_cmp(g_about_sites[i].addr, g_about_sites[i].orig, 5))
            {
                uint8_t call[5];
                encode_call(call, g_about_sites[i].addr, base + i * 0x100);
                mem_write(g_about_sites[i].addr, call, 5);
            }
        }
    }

    // --- profile till caves ---
    if (CFG_SHOW_PROFILE && g_ex.till_installed && g_ex.till_block)
    {
        auto base = reinterpret_cast<uintptr_t>(g_ex.till_block);
        for (int i = 0; i < 2; i++)
        {
            if (mem_cmp(g_till_sites[i].addr, g_till_sites[i].orig, 5))
            {
                uint8_t call[5];
                encode_call(call, g_till_sites[i].addr, base + i * 0x100);
                mem_write(g_till_sites[i].addr, call, 5);
            }
        }
    }

    // --- about NOP group ---
    if (!CFG_SHOW_ABOUT)
    {
        for (int i = 0; i < ABOUT_NOP_COUNT; i++)
        {
            if (mem_cmp(g_about_nops[i].addr, g_about_nops[i].orig, g_about_nops[i].len))
            {
                mem_nop(g_about_nops[i].addr, g_about_nops[i].len);
                g_about_nops[i].applied = true;
            }
        }
    }

    // --- profile NOP group ---
    if (!CFG_SHOW_PROFILE)
    {
        for (int i = 0; i < PROFILE_NOP_COUNT; i++)
        {
            if (mem_cmp(g_profile_nops[i].addr, g_profile_nops[i].orig, g_profile_nops[i].len))
            {
                mem_nop(g_profile_nops[i].addr, g_profile_nops[i].len);
                g_profile_nops[i].applied = true;
            }
        }
    }
}

static size_t build_extra_patch_ranges(
    std::array<patch_code_range, 64>& ranges)
{
    size_t count = 0;
    const auto add = [&](uintptr_t address, size_t size)
    {
        if (count < ranges.size())
            ranges[count++] = {address, size};
    };

    for (const uintptr_t address : ABOUT_ADDRS)
        add(address - 8, 16);

    static constexpr uintptr_t kWatermarkAddresses[] = {
        0x41516C36, 0x41516C3D, 0x41516808, 0x4151681E,
        0x41516BEB, 0x41516850, 0x41516C2A, 0x41516845,
        0x41516C1E, 0x4151E6E2, 0x4151E6F3, 0x4151E713,
        0x4151E70B
    };
    for (const uintptr_t address : kWatermarkAddresses)
        add(address - 8, 16);

    for (const TextSite& site : g_about_sites)
        add(site.addr, sizeof(site.orig));
    for (const TillSite& site : g_till_sites)
        add(site.addr, sizeof(site.orig));
    for (const NopPatch& patch : g_about_nops)
        add(patch.addr, patch.len);
    for (const NopPatch& patch : g_profile_nops)
        add(patch.addr, patch.len);

    return count;
}

static void extra_persist_cb()
{
    if (!extra_needs_repair())
        return;

    std::array<patch_code_range, 64> ranges{};
    const size_t range_count = build_extra_patch_ranges(ranges);
    run_persist_patch_transaction_locked(
        ranges.data(),
        range_count,
        extra_apply_repairs);
}

// ============================================================
//  Public entry — called once from setup_hooks()
// ============================================================

void apply_menu_extra()
{
    save_profile_floats();

    // ---- branding ----
    set_watermark(CFG_WATERMARK);
    set_about_logo(CFG_ABOUT_LOGO);

    // ---- about panel ----
    if (CFG_SHOW_ABOUT)
        install_about_text(CFG_BRANCH, CFG_UPDATED, CFG_VALID);
    else
        nop_apply(g_about_nops, ABOUT_NOP_COUNT);

    // ---- profile section ----
    if (CFG_SHOW_PROFILE)
    {
        restore_profile_floats();
        install_till(CFG_TILL_LABEL, CFG_TILL_VALUE);
    }
    else
    {
        nop_apply(g_profile_nops, PROFILE_NOP_COUNT);
        apply_profile_offset(CFG_PROFILE_OFFSET);
    }

    // ---- optional features ----
    if (CFG_HIDE_CHAT)     install_chat_hider();
    if (CFG_REDIRECT_URLS) install_url_redirects(CFG_URL_CONFIGS, CFG_URL_SCRIPTS, CFG_URL_DOCS);

    // ---- persist ----
    register_persist_callback(extra_persist_cb);
}
