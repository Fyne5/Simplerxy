#!/bin/bash

wget https://raw.githubusercontent.com/Fyne5/Simplerxy/refs/heads/main/config.conf

docker compose up -d

docker compose logs -f
