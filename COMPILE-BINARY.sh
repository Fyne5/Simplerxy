#!/bin/bash

FILE="main_1.0.0.go"

rm -f Simplerxy-*

BUILD_FLAGS="-trimpath -ldflags=-s -ldflags=-w"

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
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build $BUILD_FLAGS -o "$output" "$FILE"
  ) &
done

wait

chmod +x Simplerxy-* 2>/dev/null
chmod -x Simplerxy-*.exe 2>/dev/null

echo "Done!"
