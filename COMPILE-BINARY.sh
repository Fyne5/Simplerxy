#!/bin/bash
FILE="main_0.0.3.go"

GOOS=darwin GOARCH=amd64 go build -o Simplerxy-macos-amd64 $FILE
GOOS=darwin GOARCH=arm64 go build -o Simplerxy-macos-arm64 $FILE
GOOS=linux GOARCH=amd64 go build -o Simplerxy-linux-amd64 $FILE
GOOS=linux GOARCH=arm64 go build -o Simplerxy-linux-arm64 $FILE
GOOS=linux GOARCH=386 go build -o Simplerxy-linux-386 $FILE

chmod +x Simplerxy-*
