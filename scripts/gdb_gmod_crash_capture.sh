#!/usr/bin/env bash
set -euo pipefail

GAME_DIR="${GAME_DIR:-/home/sweat/.local/share/Steam/steamapps/common/GarrysMod}"
APPID="${APPID:-4000}"
OUT_DIR="${OUT_DIR:-/tmp/gmod-gdb-crash-$(date +%Y%m%d-%H%M%S)}"
POLL_SECONDS="${POLL_SECONDS:-45}"
STEAM_BIN="${STEAM_BIN:-steam}"
GDB_BIN="${GDB_BIN:-gdb}"

mkdir -p "$OUT_DIR"

before_pids="$(mktemp)"
after_pids="$(mktemp)"
gdb_cmds="$(mktemp)"
trap 'rm -f "$before_pids" "$after_pids" "$gdb_cmds"' EXIT

pgrep -u "$USER" -f "$GAME_DIR/bin/linux64/gmod" > "$before_pids" 2>/dev/null || true

"$STEAM_BIN" -applaunch "$APPID" > "$OUT_DIR/steam-applaunch.log" 2>&1 &
steam_launch_pid=$!

target_pid=""
deadline=$((SECONDS + POLL_SECONDS))
while [ "$SECONDS" -lt "$deadline" ]; do
    pgrep -u "$USER" -f "$GAME_DIR/bin/linux64/gmod" > "$after_pids" 2>/dev/null || true
    target_pid="$(comm -13 <(sort -n "$before_pids") <(sort -n "$after_pids") | tail -n 1 || true)"
    if [ -n "$target_pid" ]; then
        break
    fi
    sleep 0.05
done

if [ -z "$target_pid" ]; then
    echo "Timed out waiting for GMod process. Output: $OUT_DIR" >&2
    wait "$steam_launch_pid" 2>/dev/null || true
    exit 1
fi

cat > "$gdb_cmds" <<GDB
set pagination off
set confirm off
set print thread-events off
set breakpoint pending on
set detach-on-fork off
set follow-fork-mode child
handle SIGSEGV stop print nopass
handle SIGABRT stop print nopass
handle SIGILL stop print nopass
handle SIGBUS stop print nopass
handle SIGTRAP stop print nopass
set logging file $OUT_DIR/gdb-crash-report.txt
set logging overwrite on
set logging redirect off
set logging enabled on
printf "=== attached ===\\n"
info inferior
info proc
info files
info sharedlibrary
printf "\\n=== continuing until crash signal ===\\n"
continue
printf "\\n=== stopped ===\\n"
info threads
thread apply all bt full 32
printf "\\n=== registers ===\\n"
info registers
printf "\\n=== disassembly around pc ===\\n"
x/32i \$pc-64
printf "\\n=== mapped files ===\\n"
info proc mappings
set logging enabled off
detach
quit
GDB

echo "$target_pid" > "$OUT_DIR/gmod.pid"
echo "Attaching GDB to PID $target_pid. Output: $OUT_DIR"
"$GDB_BIN" -q -p "$target_pid" -x "$gdb_cmds" 2>&1 | tee "$OUT_DIR/gdb-console.log"
