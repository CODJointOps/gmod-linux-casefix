# gmod-patcher

A community patcher for **Garry's Mod on Linux**. It fixes a set of long-standing
native bugs that Facepunch has never fixed on Linux — missing textures/models,
startup crashes, and the join/reconnect crashes-and-hangs that plague busy
servers.

You run one command. It does the rest. No injectors, no DLLs to drag onto the
window, no launch options to memorize.

## What it fixes

| Fix | Bug it works around |
|-----|---------------------|
| **Case-insensitive file lookups** | Linux filesystems are case-sensitive; GMod/Source ask for paths in the wrong case, so textures and models silently fail to load. The patcher retries missing read-only paths with the real on-disk letter case. |
| **SwiftShader layout repair** | On current builds CEF looks for `bin/linux64/swiftshader/libGLESv2.so` etc. which the game doesn't ship there. Startup crashes with `swiftshader/libGLESv2.so` missing in `chromium.log`. The patcher adds the missing symlinks. |
| **Join/reconnect crash guard** | A native GMod bug: during connect the engine runs server-provided client Lua without a protecting `pcall`, so a buggy addon error escalates to a hard crash or a stuck "loading…" hang. Reconnecting to a heavy server broke ~50% of the time. The patch recovers the error locally and lets the connect finish. |
| **Certificate crash (OpenSSL)** | The Steam runtime's OpenSSL 1.0.0 needs locking callbacks the game never installs, so concurrent cert verification during join races and crashes (`RSA_new_method` / X509 SIGSEGV). The patch installs the missing callbacks. |

## How it works (and why that matters)

The patcher does **not** inject into a running game. Instead, `apply` adds one
`DT_NEEDED` entry to the game's own `filesystem_stdio_client.so`. That's the
standard Linux mechanism a program uses to list its libraries — so when GMod
starts, the OS loader pulls our single helper `.so` (`libgmod_patch.so`) in
automatically, exactly like any of the game's other libraries. The original file
is backed up first, and `remove` restores it.

`filesystem_stdio_client.so` is loaded by the game client — and by listen servers,
since "host a multiplayer game" runs inside the client process — so patching that
one file covers every player. Standalone dedicated servers (`filesystem_stdio.so`)
are intentionally out of scope.

Once loaded, the helper installs the fixes in-process: the filesystem fixes via
GOT-entry redirection, and the join/reconnect + certificate fixes via inline
hooks of engine/Lua functions, applied on a background thread once those modules
are mapped. Logs go to `/tmp/gmod_patcher.log`.

## ⚠️ Read this before you use it

**This is the dangerous kind of patch.** To fix the connect crashes it hooks
engine and Lua functions at runtime — the same *category* of technique a cheat
uses. An anti-cheat that inspected the game's memory could absolutely notice it.

What you should know going in:

- **VAC has never been known to work in Garry's Mod, and especially not on
  Linux.** That is not a guarantee of anything — it's just the long-standing
  reality. Don't treat "VAC is broken" as "I'm safe."
- **The author has been running this and nothing has happened.** That is an
  anecdote, not a promise. Your account is your risk.
- **Servers can run their own checks.** Even with VAC out of the picture, a
  server-side anti-cheat or admin could flag or ban you. We have no control over
  that.
- **We are not responsible for bans, lost items, or anything else.** If you run
  this and lose your account, that is on you. By using it you accept that.

If a banned account would upset you, don't use this on that account. You have
been warned plainly and on purpose.

You can disable any individual runtime patch without rebuilding by setting an
environment variable before launching GMod, e.g.
`GMOD_PATCHER_DISABLE=gmod_reconnect_crash_guard`.

## Build

```bash
cmake -S . -B build
cmake --build build -j
```

Produces the `gmod-patcher` CLI plus the helper library `libgmod_patch.so` next
to it.

## Use

```bash
./build/gmod-patcher status   # show what's patched
./build/gmod-patcher apply    # install all fixes
./build/gmod-patcher remove   # restore the originals
./build/gmod-patcher apply --game-dir /path/to/GarrysMod
```

`apply`/`status`/`remove` auto-detect your GarrysMod install from the usual Steam
library locations; pass `--game-dir` to point at it explicitly. Run the CLI from
the directory that holds the helper `.so` files (the build output directory).
