#include "patches/patch_api.h"
#include "vendor/safetyhook/safetyhook.hpp"

#include <csetjmp>
#include <cstddef>
#include <cstdint>
#include <dlfcn.h>

// GMod join/reconnect crash mitigation (LINUX ONLY -- this is a native Linux
// GMod bug that reproduces in vanilla too; injection just makes it more frequent).
//
// Root cause (verified live, GDB): during join/reconnect (and sometimes the
// spawn/main menu) GMod runs Lua callbacks from engine C++ WITHOUT a protecting
// lua_pcall. When that Lua errors, gLua escalates to a fatal exit through several
// different primitives depending on the call site and context, ALL of which kill
// the process:
//   - C++ throw -> std::terminate -> abort()       (engine frames aren't
//     unwindable, so a try/catch in our hook can't catch it)
//   - libtier0 Error() -> _exit(100)
//   - libtier0 Error() -> Plat_ExitProcess() (which does *(int*)0=1 for a
//     minidump, then _exit) -> SIGSEGV/exit
// and the error fires at MULTIPLE call sites (net CNetChan::ProcessMessages AND
// menu/VGUI paint), so a per-call-site catch is whack-a-mole.
//
// Mitigation: the real fix (local recovery at the lua_gettable/getfield boundary)
// plus several belts. See each detour for the full reasoning. The throughline:
// recover at the cleanest primitive with the right granularity so the connect
// batch FINISHES (no crash, no stuck-loading hang).
namespace patches::gmod {
namespace {

SafetyHookInline g_call_hook{};       // CLuaInterface::Call (lua_shared slot 10) -- make it protected
SafetyHookInline g_gettable_hook{};   // lua_gettable -- catch C++ throw at the lua boundary
SafetyHookInline g_getfield_hook{};   // lua_getfield -- catch C++ throw at the lua boundary
SafetyHookInline g_lua_error_hook{};  // CLuaInterface::DoStackCheck (lua_shared) -- leaked-stack rebalance
SafetyHookInline g_pm_hook{};         // CNetChan::ProcessMessages (coarse outer barrier)
SafetyHookInline g_msg_hook{};        // per-message netmsg->Process() (fine inner barrier -- the real fix)
SafetyHookInline g_abort_hook{};      // libc abort()
SafetyHookInline g_exit_hook{};       // libc exit()
SafetyHookInline g_uexit_hook{};      // libc _exit()
SafetyHookInline g_plat_exit_hook{};  // libtier0 Plat_ExitProcess()

// Innermost active recovery barrier on this thread (nested barriers save/restore
// it). A fatal-exit primitive longjmps to the nearest enclosing barrier so the
// least in-flight work is abandoned. Thread-local: exits on other threads, or
// outside any barrier, run for real.
thread_local std::jmp_buf* g_active_barrier = nullptr;

[[noreturn]] void abort_detour() {
    if (g_active_barrier) std::longjmp(*g_active_barrier, 1);
    g_abort_hook.call<void>();
    __builtin_unreachable();
}
[[noreturn]] void exit_detour(int status) {
    if (g_active_barrier) std::longjmp(*g_active_barrier, 1);
    g_exit_hook.call<void>(status);
    __builtin_unreachable();
}
[[noreturn]] void uexit_detour(int status) {
    if (g_active_barrier) std::longjmp(*g_active_barrier, 1);
    g_uexit_hook.call<void>(status);
    __builtin_unreachable();
}
[[noreturn]] void plat_exit_detour(int status) {
    if (g_active_barrier) std::longjmp(*g_active_barrier, 1);
    g_plat_exit_hook.call<void>(status);
    __builtin_unreachable();
}

// Lua C-API (lua_shared exports). LUA_MULTRET == -1.
int (*g_lua_gettop)(void*) = nullptr;
void (*g_lua_settop)(void*, int) = nullptr;
int (*g_lua_pcall)(void*, int, int, int) = nullptr;
void (*g_lua_pushnil)(void*) = nullptr;
const char* (*g_lua_tolstring)(void*, int, size_t*) = nullptr;

// CLuaInterface::Call (lua_shared vtable slot 10) is the UNPROTECTED entry: it runs
// raw lua_call(L, nargs, nresults) and, if that Lua errors, gLua longjmps/throws
// fatally (no pcall barrier) -> the reconnect-batch crash. We reimplement it as the
// protected PCall equivalent: lua_pcall catches the error LOCALLY with real Lua
// state cleanup (unlike the setjmp net barrier, which abandons the batch and leaves
// L internally corrupt -> the stuck-loading hang), log once, restore the stack to
// Call's contract, then run the original's vtable[50](this, L) tail-fixup. The
// caller (engine/VGUI net dispatch) resumes normally so the connect batch FINISHES.
// Also hardens the client against ANY server's buggy client-side Lua. BN: Call
// returns void (it tailcalls the void vtable[50]=CLuaInterface::SetLuaState).
void call_detour(void* self, int nargs, int nresults) {
    void* L = reinterpret_cast<void**>(self)[1];      // this->m_lua (offset 8)
    int base = g_lua_gettop(L) - nargs - 1;           // slot where the function sits
    if (g_lua_pcall(L, nargs, nresults, 0) != 0) {    // protected: proper Lua recovery
        const char* err = g_lua_tolstring(L, -1, nullptr);
        LOG_ONCE("patch[gmod_reconnect_crash_guard]: caught server-side Lua error in "
                 "unprotected Call (kept connect alive): %s", err ? err : "?");
        g_lua_settop(L, base);                        // drop pcall's error object
        if (nresults != -1)                           // LUA_MULTRET -> leave 0 results
            for (int i = 0; i < nresults; ++i) g_lua_pushnil(L);
    }
    void** vt = *reinterpret_cast<void***>(self);     // replicate Call's tail:
    reinterpret_cast<void (*)(void*, void*)>(vt[50])(self, L);  // m_lua = L (void)
}

// CLuaInterface::DoStackCheck replacement. BN decompile: the original calls
// vtable[0](this) == lua_gettop(this->m_lua) to measure stack imbalance, and if it
// is non-zero hard-calls libtier0 Error("...Lua Stack Leak...") -> process death.
// It is checked at points where the Lua stack is expected to be empty (baseline 0),
// so a non-zero top is genuinely leaked garbage from a Lua call that errored or
// returned unbalanced (common during reconnect). The original just crashes; merely
// no-op'ing it leaves the garbage on the stack so the next connect/spawn Lua runs
// dirty (script errors, stuck loading). Instead we do what the check SHOULD do:
// rebalance -- lua_settop(L, 0) to drop the leak -- then continue. this[1] is the
// lua_State (arg1[1], used as the State by the callers). Returns 0; callers ignore.
int dostackcheck_detour(void* self) {
    if (g_lua_gettop && g_lua_settop) {
        void* L = reinterpret_cast<void**>(self)[1];
        if (L) {
            int top = g_lua_gettop(L);
            if (top != 0) {
                g_lua_settop(L, 0);  // clear the leaked values -> clean baseline
                LOG_ONCE("patch[gmod_reconnect_crash_guard]: rebalanced a leaked Lua "
                         "stack (top=%d) instead of crashing on 'Lua Stack Leak'", top);
            }
        }
    }
    return 0;
}

// Universal protection for the C++ -> Lua table-access boundary. GDB proved the
// reconnect crash also fires OUTSIDE net dispatch -- from VGUI panel paint/think: a
// server addon's client Lua errors inside a raw lua_gettable/lua_getfield called
// from C++ with no reachable pcall. A server addon's bad index errors via TWO
// different gLua mechanisms depending on whether L->errorJmp is set: (1) errorJmp
// null -> luaD_throw calls the lua_atpanic handler -> libtier0 Error() -> _exit (the
// NET-dispatch path); (2) errorJmp set -> C++ throw that unwinds up through
// non-unwindable engine/vgui frames -> std::terminate -> abort (the VGUI paint
// path). We catch BOTH right here and recover LOCALLY -- push nil where the result
// belongs and return -- so the C++ caller (net message handler, panel paint,
// anything) FINISHES instead of crashing OR being skipped. A finer-grained "skip the
// whole net message" barrier is wrong: the failing message also carries the work
// that dismisses the loading panel, so skipping it hangs the connect. Local
// nil-recovery lets the message complete. "attempt to index a nil value" is a
// luaG_typeerror raised before any metamethod call, so no CallInfo frame was pushed
// -- restoring the stack top is a clean recovery (no ci corruption). setjmp barrier
// catches mechanism (1) (our fatal-exit detours longjmp to the innermost
// g_active_barrier = this one); try/catch catches mechanism (2). lua_shared is built
// -fexceptions so its frames are unwindable and the catch is reachable.
int gettable_detour(void* L, int idx) {  // lua_gettable(L, idx): pops key, pushes value
    int base = g_lua_gettop ? g_lua_gettop(L) : 0;
    std::jmp_buf jb;
    std::jmp_buf* prev = g_active_barrier;
    if (setjmp(jb) != 0) {  // mechanism (1): panic -> Error -> _exit -> longjmp'd here
        g_active_barrier = prev;
        if (g_lua_settop) g_lua_settop(L, base > 0 ? base - 1 : 0);
        if (g_lua_pushnil) g_lua_pushnil(L);
        LOG_ONCE("patch[gmod_reconnect_crash_guard]: recovered a server-side Lua error in "
                 "lua_gettable locally (-> nil); the C++ caller continues, connect completes");
        return 0;  // LUA_TNIL
    }
    g_active_barrier = &jb;
    try {
        int r = g_gettable_hook.original<int (*)(void*, int)>()(L, idx);
        g_active_barrier = prev;
        return r;
    } catch (...) {  // mechanism (2): C++ throw caught before it reaches std::terminate
        g_active_barrier = prev;
        if (g_lua_settop) g_lua_settop(L, base > 0 ? base - 1 : 0);
        if (g_lua_pushnil) g_lua_pushnil(L);
        LOG_ONCE("patch[gmod_reconnect_crash_guard]: caught a server-side Lua throw in "
                 "lua_gettable (-> nil) before it could std::terminate");
        return 0;
    }
}
int getfield_detour(void* L, int idx, const char* k) {  // lua_getfield: pushes t[k], pops nothing
    int base = g_lua_gettop ? g_lua_gettop(L) : 0;
    std::jmp_buf jb;
    std::jmp_buf* prev = g_active_barrier;
    if (setjmp(jb) != 0) {
        g_active_barrier = prev;
        if (g_lua_settop) g_lua_settop(L, base);
        if (g_lua_pushnil) g_lua_pushnil(L);
        LOG_ONCE("patch[gmod_reconnect_crash_guard]: recovered a server-side Lua error in "
                 "lua_getfield locally (-> nil); the C++ caller continues");
        return 0;
    }
    g_active_barrier = &jb;
    try {
        int r = g_getfield_hook.original<int (*)(void*, int, const char*)>()(L, idx, k);
        g_active_barrier = prev;
        return r;
    } catch (...) {
        g_active_barrier = prev;
        if (g_lua_settop) g_lua_settop(L, base);
        if (g_lua_pushnil) g_lua_pushnil(L);
        LOG_ONCE("patch[gmod_reconnect_crash_guard]: caught a server-side Lua throw in "
                 "lua_getfield (-> nil) before it could std::terminate");
        return 0;
    }
}

// Per-message barrier -- the connect batch's failing message recovers at the single
// netmsg->Process() (returns true so the ProcessMessages while(true) loop treats it
// as handled and CONTINUES), instead of the coarse barrier below longjmping PAST the
// whole loop (which abandons the messages that dismiss the loading panel -> hang).
// The fatal-exit detours longjmp to the innermost g_active_barrier, so nesting this
// inside the ProcessMessages barrier makes recovery abandon ONLY the one bad message.
bool process_one_message_detour(void* self, void* arg2) {
    std::jmp_buf buf;
    std::jmp_buf* prev = g_active_barrier;
    if (setjmp(buf) != 0) {
        g_active_barrier = prev;
        LOG_ONCE("patch[gmod_reconnect_crash_guard]: recovered an unprotected gLua error "
                 "in a single net message (batch continues, no hang)");
        return true;  // tell ProcessMessages this message processed OK -> loop continues
    }
    g_active_barrier = &buf;
    bool ret = g_msg_hook.original<bool (*)(void*, void*)>()(self, arg2);
    g_active_barrier = prev;
    return ret;
}

// Coarse outer barrier: fallback for unprotected errors in message types whose
// Process() is not the one we wrap above (keeps general crash coverage).
bool process_messages_detour(void* self, void* msg) {
    std::jmp_buf buf;
    std::jmp_buf* prev = g_active_barrier;
    if (setjmp(buf) != 0) {
        g_active_barrier = prev;
        LOG_ONCE("patch[gmod_reconnect_crash_guard]: recovered an unprotected gLua "
                 "error in net dispatch (would have crashed the game)");
        return true;  // claim handled so CNetChan keeps the channel
    }
    g_active_barrier = &buf;
    // original() not .call<>(): a longjmp through this call must not strand the hook
    // mutex locked.
    bool ret = g_pm_hook.original<bool (*)(void*, void*)>()(self, msg);
    g_active_barrier = prev;
    return ret;
}

void* resolve_export(const char* module, const char* sym) {
    void* h = memory::get_module_handle(module);
    return h ? dlsym(h, sym) : nullptr;
}

bool hook_at(SafetyHookInline& slot, void* fn, void* detour) {
    if (slot) {
        return true;
    }
    if (!fn || !memory::is_executable_addr(reinterpret_cast<std::uintptr_t>(fn))) {
        return false;
    }
    slot = safetyhook::create_inline(fn, detour);
    return static_cast<bool>(slot);
}

bool install() {
    if (g_call_hook && g_lua_error_hook && g_pm_hook && g_msg_hook && g_abort_hook &&
        g_exit_hook && g_uexit_hook && g_plat_exit_hook) {
        return true;
    }
    if (!memory::get_module_handle("engine_client.so") ||
        !memory::get_module_handle("lua_shared_client.so")) {
        return false;  // modules not mapped yet -> retry next reconcile
    }
    // Fatal-exit primitives are the recovery mechanism; they MUST be hooked (and
    // before any barrier runs). Stable libc / libtier0 symbols -- a miss here is
    // unexpected and means recovery is impossible, so fail and retry.
    if (!hook_at(g_abort_hook, dlsym(RTLD_DEFAULT, "abort"), reinterpret_cast<void*>(&abort_detour)) ||
        !hook_at(g_exit_hook, dlsym(RTLD_DEFAULT, "exit"), reinterpret_cast<void*>(&exit_detour)) ||
        !hook_at(g_uexit_hook, dlsym(RTLD_DEFAULT, "_exit"), reinterpret_cast<void*>(&uexit_detour)) ||
        !hook_at(g_plat_exit_hook, resolve_export("libtier0_client.so", "Plat_ExitProcess"),
                 reinterpret_cast<void*>(&plat_exit_detour))) {
        return false;
    }
    // Lua C-API for the rebalance (lua_shared exports). If these miss, the detour
    // falls back to a plain no-op (still no crash, just no rebalance).
    g_lua_gettop = reinterpret_cast<int (*)(void*)>(resolve_export("lua_shared_client.so", "lua_gettop"));
    g_lua_settop = reinterpret_cast<void (*)(void*, int)>(resolve_export("lua_shared_client.so", "lua_settop"));
    g_lua_pcall = reinterpret_cast<int (*)(void*, int, int, int)>(resolve_export("lua_shared_client.so", "lua_pcall"));
    g_lua_pushnil = reinterpret_cast<void (*)(void*)>(resolve_export("lua_shared_client.so", "lua_pushnil"));
    g_lua_tolstring = reinterpret_cast<const char* (*)(void*, int, size_t*)>(resolve_export("lua_shared_client.so", "lua_tolstring"));
    // CLuaInterface::Call (lua_shared vtable slot 10) -- THE primary fix: make the
    // unprotected entry protected. Internal (not exported); resolved by signature,
    // unique on disk (PCall's prologue has 41 55 here, so no collision). rel32
    // wildcarded. Needs the lua exports above; if any miss we skip the Call hook.
    void* call_fn = reinterpret_cast<void*>(memory::find_signature<std::uintptr_t>(
        "lua_shared_client.so",
        "55 48 89 E5 41 54 53 48 89 FB 4C 8B 67 08 4C 89 E7 E8 ?? ?? ?? ?? "
        "48 8B 03 48 89 DF 5B 4C 89 E6"));
    // CLuaInterface::DoStackCheck (lua_shared) -- the "Lua Stack Leak" guard that
    // hard-crashes via libtier0 Error(); every captured join/reconnect crash funnels
    // through it. Internal/static (no export), resolved by signature.
    void* lua_err = reinterpret_cast<void*>(memory::find_signature<std::uintptr_t>(
        "lua_shared_client.so",
        "55 48 89 E5 41 57 41 56 41 55 49 89 FD 41 54 53 48 81 EC B8 00 00 00 "
        "48 8B 05 ?? ?? ?? ?? 8B 90 0C 10 00 00"));
    // CNetChan::ProcessMessages -- coarse outer barrier (fallback).
    void* pm = resolve_export("engine_client.so", "_ZN8CNetChan15ProcessMessagesER7bf_read");
    // The per-message netmsg->Process() that carries the failing reconnect dispatch
    // (engine_client sub_9fb790, called from the ProcessMessages loop at +0x161d63).
    // Internal/non-export -> signature (unique on disk; rel32 of its first call
    // wildcarded).
    void* msg_proc = reinterpret_cast<void*>(memory::find_signature<std::uintptr_t>(
        "engine_client.so",
        "55 48 89 E5 41 54 49 89 F4 53 48 89 FB E8 ?? ?? ?? ?? "
        "41 0F B6 44 24 28 84 C0 74 3C"));

    bool call_ok = g_lua_pcall && g_lua_gettop && g_lua_settop && g_lua_pushnil &&
                   g_lua_tolstring &&
                   hook_at(g_call_hook, call_fn, reinterpret_cast<void*>(&call_detour));
    // lua_gettable / lua_getfield C++-throw protection (the VGUI-path crash fix).
    bool gettable_ok = g_lua_gettop && g_lua_settop && g_lua_pushnil &&
        hook_at(g_gettable_hook, resolve_export("lua_shared_client.so", "lua_gettable"),
                reinterpret_cast<void*>(&gettable_detour));
    bool getfield_ok = g_lua_gettop && g_lua_settop && g_lua_pushnil &&
        hook_at(g_getfield_hook, resolve_export("lua_shared_client.so", "lua_getfield"),
                reinterpret_cast<void*>(&getfield_detour));
    bool lua_err_ok = hook_at(g_lua_error_hook, lua_err, reinterpret_cast<void*>(&dostackcheck_detour));
    bool pm_ok = hook_at(g_pm_hook, pm, reinterpret_cast<void*>(&process_messages_detour));
    bool msg_ok = hook_at(g_msg_hook, msg_proc, reinterpret_cast<void*>(&process_one_message_detour));

    // Degrade gracefully: a sig miss after a game update must NOT silently no-op the
    // whole guard. Log loudly so the fix is a sig refresh, not a crash hunt.
    if (!call_ok) {
        LOG_ONCE("patch[gmod_reconnect_crash_guard]: CLuaInterface::Call signature/export "
                 "MISS (lua_shared_client.so likely updated) -- protected-Call fix NOT installed.");
    }
    if (!lua_err_ok) {
        LOG_ONCE("patch[gmod_reconnect_crash_guard]: gLua DoStackCheck signature MISS "
                 "(lua_shared_client.so likely updated) -- leaked-stack rebalance NOT installed.");
    }
    if (!pm_ok) {
        LOG_ONCE("patch[gmod_reconnect_crash_guard]: ProcessMessages export MISS -- "
                 "coarse net barrier not installed.");
    }
    if (!msg_ok) {
        LOG_ONCE("patch[gmod_reconnect_crash_guard]: per-message Process() signature MISS "
                 "(engine_client.so likely updated) -- per-message barrier NOT installed.");
    }
    if (!gettable_ok || !getfield_ok) {
        LOG_ONCE("patch[gmod_reconnect_crash_guard]: lua_gettable/getfield export MISS "
                 "(gettable=%d getfield=%d) -- VGUI-path C++-throw protection NOT fully installed.",
                 gettable_ok, getfield_ok);
    }
    LOG_ONCE("patch[gmod_reconnect_crash_guard]: installed (call=%s gettable=%s getfield=%s "
             "stackcheck=%s net=%s msg=%s + abort/exit/_exit/Plat_ExitProcess)",
             call_ok ? "on" : "MISS", gettable_ok ? "on" : "MISS", getfield_ok ? "on" : "MISS",
             lua_err_ok ? "on" : "MISS", pm_ok ? "on" : "MISS", msg_ok ? "on" : "MISS");
    // Installed as long as the fatal hooks are live. If both barriers missed the
    // hooks are inert but harmless; returning true stops futile retries (the module
    // is mapped, the sig will not start matching later).
    return true;
}

void remove() {
    g_call_hook = {};
    g_gettable_hook = {};
    g_getfield_hook = {};
    g_lua_error_hook = {};
    g_msg_hook = {};
    g_pm_hook = {};
    g_abort_hook = {};
    g_exit_hook = {};
    g_uexit_hook = {};
    g_plat_exit_hook = {};
}

const game_patch g_patch{
    "gmod_reconnect_crash_guard",
    &install,
    &remove,
};

struct auto_register {
    auto_register() { patches::register_patch(&g_patch); }
} g_auto_register;

} // namespace
} // namespace patches::gmod
