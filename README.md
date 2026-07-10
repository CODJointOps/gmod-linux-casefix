# css-patcher

Fixes the case-sensitivity bug in **Counter-Strike: Source on Linux**. Source
asks for files in the wrong letter case (e.g. `Materials/` instead of
`materials/`), and since Linux filesystems are case-sensitive, textures and
models silently fail to load. This patcher intercepts those failing lookups and
retries them with the real on-disk letter case.

One command. No injectors, no launch options.

## How it works

`apply` adds one `DT_NEEDED` entry to the game's `filesystem_stdio.so`. When CSS
starts, the OS loader pulls in the helper `.so` (`libcss_patch.so`) automatically,
same as any other library. The original file is backed up first, and `remove`
restores it.

Once loaded, the helper redirects the filesystem module's GOT entries for
`stat`, `open`, `fopen`, `opendir`, `scandir` to wrappers that retry
case-mismatched paths. Logs go to `/tmp/css_patcher.log`.

## Build

```bash
cmake -S . -B build
cmake --build build -j
```

Produces the `css-patcher` CLI plus `libcss_patch.so` next to it.

## Use

```bash
./build/css-patcher status   # show what's patched
./build/css-patcher apply    # install the fix
./build/css-patcher remove   # restore the original
./build/css-patcher apply --game-dir /path/to/Counter-Strike Source
```

Auto-detects your CSS install from the usual Steam library locations; pass
`--game-dir` to point at it explicitly. Run the CLI from the directory that holds
the helper `.so` (the build output directory).
