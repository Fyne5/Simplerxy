#!/bin/bash

BUILD_NUM="0.0.3"

cat << EOF > Dockerfile_simplerxy
FROM alpine:3.22.0

RUN apk update && apk upgrade -a && \
    apk add --no-cache \
    iptables \
    iproute2 \
    curl \
    brotli-libs \
    libstdc++ \
    gcompat \
    dos2unix \
    tzdata \
    dumb-init

RUN mkdir -p /app/simplerxy
WORKDIR /app/simplerxy

COPY Simplerxy .
RUN chmod +x Simplerxy

EXPOSE 3979

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["./Simplerxy"]
EOF

wget -q https://github.com/Fyne5/Simplerxy/releases/download/$BUILD_NUM/Simplerxy-linux-amd64 -O Simplerxy
docker build -t $BUILD_NUM -f Dockerfile_simplerxy .
docker tag $BUILD_NUM tquang/simplerxy:$BUILD_NUM

docker push tquang/simplerxy:$BUILD_NUM

rm -rf Dockerfile_simplerxy Simplerxy
