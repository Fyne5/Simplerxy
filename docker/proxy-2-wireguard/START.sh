#!/bin/bash

#How to use: ./START <NAME_CONTAINER>

WIREGUARDCONF="./wireguard.conf"
SIMPLERXYCONF="./simplerxy.conf"
SIMPLERXYPORT="3979"

if [[ -z "$#" || "$#" -ne 1 ]]; then
  exit 0
 else

cat << EOF > Dockerfile_simplerxy
FROM alpine:3.22.0
RUN apk update && apk upgrade -a
RUN apk add --no-cache iptables iproute2 wireguard-tools-wg-quick wireguard-tools-openrc curl brotli-libs dumb-init
RUN mkdir -p /ENTRYPOINT
WORKDIR /ENTRYPOINT
#COPY Entrypoint.sh Simplerxy .
#RUN chmod +x Simplerxy Entrypoint.sh
COPY Simplerxy .
RUN chmod +x Simplerxy
EXPOSE 3979
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["./Entrypoint.sh"]
EOF

cat << EOF > Entrypoint.sh
#!/bin/bash
cleanup_wireguard() {
   wg-quick down $1
   exit 0
}
trap cleanup_wireguard SIGTERM SIGINT
wg-quick up $1
./Simplerxy
EOF
chmod 777 Entrypoint.sh

  if [[ -z `docker images | grep simplerxy-wireguard` ]]; then
   if [[ ! -f Simplerxy ]]; then
    wget -q https://github.com/Fyne5/Simplerxy/releases/download/0.0.1/Simplerxy-linux-amd64 -O Simplerxy
   fi
   docker build -t simplerxy-wireguard -f Dockerfile_simplerxy .
  fi

  docker run -d --name $1 -p $SIMPLERXYPORT:3979 \
   --cap-add NET_ADMIN --cap-add SYS_MODULE --privileged \
   -v $WIREGUARDCONF:/etc/wireguard/$1.conf -v $SIMPLERXYCONF:/ENTRYPOINT/config.conf -v ./Entrypoint.sh:/ENTRYPOINT/Entrypoint.sh \
   --restart unless-stopped simplerxy-wireguard

  echo "docker stop $1;docker rm $1;docker run -d --name $1 -p $SIMPLERXYPORT:3979 \
   --cap-add NET_ADMIN --cap-add SYS_MODULE --privileged \
   -v $WIREGUARDCONF:/etc/wireguard/$1.conf -v $SIMPLERXYCONF:/ENTRYPOINT/config.conf -v ./Entrypoint.sh:/ENTRYPOINT/Entrypoint.sh \
   --restart unless-stopped simplerxy-wireguard" > DOCKER.sh

  rm -rf Dockerfile_simplerxy Simplerxy

  sleep 3
  echo "Da xong, vui long kiem tra lai"
  docker ps -a | grep $1
  ifconfig $1
  docker logs -f $1
fi
