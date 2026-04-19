# gmod-linux-casefix

Fix missing textures and models in Linux GMOD caused by case-sensitive file lookups.

`gmod-linux-casefix apply` patches `filesystem_stdio_client.so` and `filesystem_stdio.so` to load small helper libs. Helper retries missing read-only paths with real on-disk letter case. Logs go to `/tmp/gmod_casefix.log`.

Use at your own risk. Garry's Mod anti-cheat has been weak or inconsistent for years, but that does not guarantee safety from server bans or other checks.

## Build

```bash
cmake -S . -B build
cmake --build build -j
```

## Use

```bash
./build/gmod-linux-casefix status
./build/gmod-linux-casefix apply
./build/gmod-linux-casefix remove
./build/gmod-linux-casefix apply --game-dir /path/to/GarrysMod
```
