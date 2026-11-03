#!/bin/bash

FILE="main_1.0.6.go"

if [ "$1" == "run" ]; then
    echo "Running debug with race detector..."
    CGO_ENABLED=1 go run --race "$FILE" --config config.conf
    exit 0
fi

rm -f Simplerxy-*

BUILD_FLAGS=(-trimpath "-ldflags=-s -w")
# Khi build kết hợp 2 tham số này, thì sẽ chỉ còn thấy "-trimpath=true", đó là bình thường.
# Còn "-ldflags=-s -w" sẽ không hiện trực tiếp, khi so dung lượng binary xuất ra mới thấy nhỏ hơn.
# go version -m Simplerxy-linux-amd64
# Simplerxy-linux-amd64: go1.24.4
#         path    command-line-arguments
#         build   -buildmode=exe
#         build   -compiler=gc
#         build   -trimpath=true
#         build   CGO_ENABLED=0
#         build   GOARCH=amd64
#         build   GOOS=linux
#         build   GOAMD64=v1

PLATFORMS=(
  "darwin/amd64/Simplerxy-macos-amd64"
  "darwin/arm64/Simplerxy-macos-arm64"
  "linux/amd64/Simplerxy-linux-amd64"
  "linux/arm64/Simplerxy-linux-arm64"
  "linux/386/Simplerxy-linux-386"
  "windows/amd64/Simplerxy-win-amd64.exe"
  "windows/386/Simplerxy-win-386.exe"
)

echo "Compiling..."

for entry in "${PLATFORMS[@]}"; do
  IFS="/" read -r os arch output <<< "$entry"
  (
    echo " -> Building $output ($os/$arch)..."
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build "${BUILD_FLAGS[@]}" -o "$output" "$FILE"
  ) &
done

wait

chmod +x Simplerxy-* 2>/dev/null
chmod -x Simplerxy-*.exe 2>/dev/null

echo "Done!"