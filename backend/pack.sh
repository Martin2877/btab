#!/usr/bin/env bash
# btab packaging script
# Usage:
#   ./pack.sh [dev|release] [platforms...] [--skip-frontend]
#   dev (default): incremental frontend build (only when src changed),
#                  output runnable dir release/btab_dev/
#   release:       full frontend rebuild, output release/btab_v<version>_windows_amd64.zip
#   platforms:     windows | linux | darwin | darwin-arm | all
#                  only valid with release; default is windows.
#                  `all` = windows + linux + darwin + darwin-arm
# Examples:
#   ./pack.sh                       # dev windows build
#   ./pack.sh release               # windows zip
#   ./pack.sh release linux         # linux amd64 tar.gz
#   ./pack.sh release all           # all platforms
set -euo pipefail

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$BACKEND_DIR")"
cd "$BACKEND_DIR"

MODE="dev"
SKIP_FRONTEND=0
PLATFORMS=()
for arg in "$@"; do
  case "$arg" in
    dev|release) MODE="$arg" ;;
    windows|linux|darwin|darwin-arm|all) PLATFORMS+=("$arg") ;;
    --skip-frontend) SKIP_FRONTEND=1 ;;
    *) echo "[pack] unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [[ "$MODE" == "dev" && ${#PLATFORMS[@]} -gt 0 ]]; then
  echo "[pack] platform args are only valid with release" >&2
  exit 1
fi
if [[ ${#PLATFORMS[@]} -eq 0 ]]; then
  PLATFORMS=(windows)
elif [[ " ${PLATFORMS[*]} " == *" all "* ]]; then
  PLATFORMS=(windows linux darwin darwin-arm)
fi

# ---------- 1. frontend ----------
need_frontend_build() {
  [[ ! -f "$ROOT_DIR/frontend/dist/index.html" ]] && return 0
  [[ -n "$(find "$ROOT_DIR/frontend/src" -type f -newer "$ROOT_DIR/frontend/dist/index.html" -print -quit 2>/dev/null)" ]] && return 0
  return 1
}

if [[ "$SKIP_FRONTEND" == 1 ]]; then
  echo "[pack] skip frontend build"
elif [[ "$MODE" == "release" ]] || need_frontend_build; then
  echo "[pack] building frontend ..."
  (cd "$ROOT_DIR/frontend" && npm run build)
else
  echo "[pack] frontend dist is up to date, skip build"
fi

# ---------- 2. sync embed assets ----------
echo "[pack] sync web/dist ..."
rm -rf web/dist
cp -r "$ROOT_DIR/frontend/dist" web/dist
mkdir -p web/dist/assets
rm -rf web/dist/assets/cyberchef
cp -r web/cyberchef web/dist/assets/cyberchef

VERSION="$(sed -n 's/^const Version = "\(.*\)"/\1/p' pkg/conf/default.go)"
echo "[pack] version: $VERSION"

# stage 通用文件（除可执行文件外保持一致）
stage_common() {
  local stage="$1"
  cp config.yaml "$stage/"
  cp "$ROOT_DIR/README.md" "$stage/"
  [[ -f btab.sqlite ]] && cp btab.sqlite "$stage/"
  cp -r stores "$stage/"
  cp -r "$ROOT_DIR/wireshark" "$stage/"
}

# release 包使用目标平台的系统默认 tshark 路径，不携带开发者本机路径；
# 该路径不可用时程序仍会自动探测（TSHARK 环境变量 / PATH / 常见安装目录）
release_tshark_path() {
  case "$1" in
    windows) echo 'C:\Program Files\Wireshark\tshark.exe' ;;
    darwin)  echo '/Applications/Wireshark.app/Contents/MacOS/tshark' ;;
    *)       echo '/usr/bin/tshark' ;;
  esac
}

set_tshark_path() {
  local cfg="$1" val="$2" esc
  esc="${val//\\/\\\\}" # sed 替换串中的反斜杠需转义
  sed -i \
    -e "s|^\([[:space:]]*tsharkpath:\).*|\1 $esc|" \
    -e "s|^\(#[[:space:]]*tsharkpath:\).*|\1 $esc|" \
    "$cfg"
}

build_one() {
  local goos="$1" goarch="$2" bin="$3"
  echo "[pack] go build ${goos}/${goarch} -> $bin"
  GOOS="$goos" GOARCH="$goarch" go build -o "$bin"
}

# ---------- dev ----------
if [[ "$MODE" == "dev" ]]; then
  build_one windows amd64 btab.exe
  STAGE="$ROOT_DIR/release/btab_dev"
  echo "[pack] staging -> $STAGE"
  rm -rf "$STAGE"
  mkdir -p "$STAGE"
  cp btab.exe "$STAGE/"
  stage_common "$STAGE"
  echo "[pack] done -> $STAGE"
  echo "[pack] run $STAGE/btab.exe to check"
  exit 0
fi

# ---------- release ----------
for p in "${PLATFORMS[@]}"; do
  case "$p" in
    windows)    GOOS=windows GOARCH=amd64 BIN=btab.exe ;;
    linux)      GOOS=linux   GOARCH=amd64 BIN=btab ;;
    darwin)     GOOS=darwin  GOARCH=amd64 BIN=btab ;;
    darwin-arm) GOOS=darwin  GOARCH=arm64 BIN=btab ;;
  esac
  PKG="btab_v${VERSION}_${GOOS}_${GOARCH}"
  STAGE="$ROOT_DIR/release/$PKG/btab"

  build_one "$GOOS" "$GOARCH" "release_bin_$BIN"
  echo "[pack] staging -> $STAGE"
  rm -rf "$STAGE"
  mkdir -p "$STAGE"
  cp "release_bin_$BIN" "$STAGE/$BIN"
  stage_common "$STAGE"
  rm -f "release_bin_$BIN"
  set_tshark_path "$STAGE/config.yaml" "$(release_tshark_path "$GOOS")"
  echo "[pack] tsharkPath -> $(release_tshark_path "$GOOS")"

  PKG_PATH="$ROOT_DIR/release/$PKG"
  if [[ "$GOOS" == "windows" ]]; then
    ZIP="$ROOT_DIR/release/${PKG}.zip"
    rm -f "$ZIP"
    powershell -NoProfile -Command "Compress-Archive -Path '$(cygpath -w "$STAGE")' -DestinationPath '$(cygpath -w "$ZIP")' -CompressionLevel Optimal"
    echo "[pack] done -> $ZIP"
  else
    TAR="$ROOT_DIR/release/${PKG}.tar.gz"
    rm -f "$TAR"
    tar -czf "$TAR" -C "$STAGE" .
    echo "[pack] done -> $TAR"
  fi
done
