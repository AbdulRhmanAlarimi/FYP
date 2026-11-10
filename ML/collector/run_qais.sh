#!/usr/bin/env bash
# run_qais.sh - start the whole stack, install the latest APK, then choose
# to collect GENUINE (benign) behaviour or ATTACK behaviour.
# Must be run from anywhere; it resolves its own directory.
set -u

COLLECTOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$COLLECTOR_DIR/../.." && pwd)"
VENV_PY="$COLLECTOR_DIR/.venv/bin/python"
LOG_DIR="/tmp/opencode"
mkdir -p "$LOG_DIR"

HOOK_PORT=8000; BACKEND_PORT=8888; APPIUM_PORT=4723
BACKEND_DIR="$ROOT/Android-InsecureBankv2-master/AndroLabServer"
HOOK_DIR="$ROOT/serverSide/testHook"

# Newest APK wins (debug build first, prebuilt root apk as fallback)
APK="$(find "$ROOT/Android-InsecureBankv2-master/InsecureBankv2/app/build/outputs/apk" \
        -name 'app-debug.apk' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)"
[ -z "${APK:-}" ] && APK="$ROOT/Android-InsecureBankv2-master/InsecureBankv2.apk"

up() { curl -s -o /dev/null -m 2 "http://127.0.0.1:$1/$2"; }
start() { # name cmd...  (nohup + log, detached)
  local name="$1"; shift
  echo ">> starting $name ..."
  setsid nohup "$@" > "$LOG_DIR/$name.log" 2>&1 < /dev/null &
}
wait_for() { # port path label timeout_s
  local tries=$(( $4 / 2 ))
  while [ $tries -gt 0 ]; do up "$1" "$2" && { echo ">> $3 ready"; return 0; }; sleep 2; tries=$((tries-1)); done
  echo "!! $3 did not come up - see $LOG_DIR/*.log"; return 1
}

echo "== stack =="
up $HOOK_PORT events    || { start hook    "$VENV_PY" -m uvicorn src.app:app --host 0.0.0.0 --port $HOOK_PORT; }
up $BACKEND_PORT login  || { (cd "$BACKEND_DIR" && start backend "$VENV_PY" app.py); }
up $APPIUM_PORT status  || { start appium appium; }
adb devices | grep -q "emulator-5554" || { start emulator emulator -avd AndroGOAT -no-window -no-audio -gpu angle_indirect -no-boot-anim; }

wait_for $HOOK_PORT    events "" 30
wait_for $BACKEND_PORT login  "" 30
wait_for $APPIUM_PORT  status "" 30
adb wait-for-device
for i in $(seq 1 30); do [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break; sleep 3; done
echo ">> emulator booted: $(adb shell getprop sys.boot_completed | tr -d '\r')"

echo "== install latest APK =="
echo ">> $APK"
adb install -r "$APK" 2>&1 | tail -1

cd "$COLLECTOR_DIR" || exit 1
echo
echo "Choose what to collect:"
echo "  1) Genuine (benign) behaviour  - collect.py"
echo "  2) Attack behaviour           - collect_attacks_qais.py (all classes, both modes)"
echo "  3) Both"
echo "  0) Exit"
read -r -p "Option: " OPT

case "$OPT" in
  1) read -r -p "Number of user flows: " N; echo "$N" | "$VENV_PY" collect.py ;;
  2) read -r -p "Sessions per attack class [1]: " N; "$VENV_PY" collect_attacks_qais.py --mode both --per-attack "${N:-1}" ;;
  3) read -r -p "Number of genuine flows: " N; echo "$N" | "$VENV_PY" collect.py
     read -r -p "Sessions per attack class [1]: " M; "$VENV_PY" collect_attacks_qais.py --mode both --per-attack "${M:-1}" ;;
  0|*) echo "bye" ;;
esac

echo "== results =="
tail -n +2 ../datasets/labels.csv | tail -5
