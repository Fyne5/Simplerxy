#!/bin/bash

docker exec -it simplerxy ip route add 172.18.0.0/16 via 172.18.0.1 dev eth0 metric 50
docker exec -it simplerxy ip rule add to 172.18.0.0/16 table main priority 100

docker exec -it simplerxy ip route add 192.168.20.0/24 via 172.18.0.1 dev eth0 metric 50
docker exec -it simplerxy ip rule add to 192.168.20.0/24 table main priority 100

docker exec -it simplerxy ip route show
