#!/bin/bash
# Compile InsecureBankv2 debug APK and place it in paths used by start-demo.sh/demo env.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_PROJECT="$ROOT/Android-InsecureBankv2-master/InsecureBankv2"
DEMO_DIR="${DEMO_DIR:-}"

JDK8_HOME="${JDK8_HOME:-/usr/lib/jvm/java-8-openjdk-amd64}"
if [[ ! -x "$JDK8_HOME/bin/java" ]]; then
  echo "error: JDK 8 is required for Gradle 4.10.1 / AGP 3.3.2 (set JDK8_HOME: $JDK8_HOME)" >&2
  exit 1
fi
export JAVA_HOME="$JDK8_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

if [[ ! -d "$ANDROID_PROJECT" ]]; then
  echo "error: Android project not found at $ANDROID_PROJECT" >&2
  exit 1
fi

echo "==> Building debug APK..."
cd "$ANDROID_PROJECT"
chmod +x ./gradlew 2>/dev/null || true
./gradlew assembleDebug

APK_SRC="$ANDROID_PROJECT/app/build/outputs/apk/debug/app-debug.apk"
if [[ ! -f "$APK_SRC" ]]; then
  echo "error: built APK not found at $APK_SRC" >&2
  exit 1
fi

echo "==> Built: $APK_SRC"

# Local copies (workspace)
LOCAL_APK="$ROOT/Android-InsecureBankv2-master/InsecureBankv2/app/build/outputs/apk/debug/app-debug.apk"
cp -f "$APK_SRC" "$ROOT/Android-InsecureBankv2-master/InsecureBankv2.apk"
echo "==> Copied to: $ROOT/Android-InsecureBankv2-master/InsecureBankv2.apk"
if [[ "$APK_SRC" != "$LOCAL_APK" ]]; then
  mkdir -p "$(dirname "$LOCAL_APK")"
  cp -f "$APK_SRC" "$LOCAL_APK"
  echo "==> Copied to: $LOCAL_APK"
fi

# Demo copies (start-demo.sh uses DEMO_DIR=/home/qais/demo)
if [[ -d "$DEMO_DIR" && "$DEMO_DIR" != "$ROOT" ]]; then
  mkdir -p "$DEMO_DIR/Android-InsecureBankv2-master/InsecureBankv2/app/build/outputs/apk/debug"
  cp -f "$APK_SRC" "$DEMO_DIR/Android-InsecureBankv2-master/InsecureBankv2.apk"
  cp -f "$APK_SRC" "$DEMO_DIR/Android-InsecureBankv2-master/InsecureBankv2/app/build/outputs/apk/debug/app-debug.apk"
  echo "==> Copied to demo: $DEMO_DIR/Android-InsecureBankv2-master/InsecureBankv2.apk"
  echo "==> Copied to demo: $DEMO_DIR/Android-InsecureBankv2-master/InsecureBankv2/app/build/outputs/apk/debug/app-debug.apk"
else
  echo "==> Demo dir not found ($DEMO_DIR); skipped demo copy (set DEMO_DIR to override)"
fi

echo "==> Done."
