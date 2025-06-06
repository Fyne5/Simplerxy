## Mô tả / Describes
Simplerxy kết hợp WireguardVPN trong từng container. Mục đích xài cho cái gì thì tự người dùng quyết định. Có thể gợi ý là: WPAD.DAT

Simpler bundles Wireguard VPN in each container. What you use it for is up to you. Suggestions include: WPAD.DAT

## Cách chạy / How to run
Chỉnh nội dung wireguard.conf và simplerxy.conf cho phù hợp các yếu tố. Chạy tạo ra container.

Edit wireguard.conf and simplerxy.conf to suit your needs. Run the container creation.
```
chmod +x START.sh
./START.sh <your container name>
```
Nếu chạy nhiều container thì có thể trùng port, chỉnh sửa SIMPLERXYPORT trong START.sh

If running multiple containers, there may be duplicate ports, edit SIMPLERXYPORT in START.sh
```
SIMPLERXYPORT=6969
```

## Cách xài / How to use
Từ đâu đó, chạy thử 2 lệnh curl sau để kiểm tra (giả bộ máy ảo chạy Simplerxy Wireguad có IP là 192.168.200.105)

From somewhere, run the following 2 curl commands to test (pretend the virtual machine running Simplerxy Wireguad has IP 192.168.200.105)

```
curl http://ipinfo.io/ip
curl http://ipinfo.io/ip -x http://192.168.200.105:3979
```
## Lưu ý với host chạy docker / Note for docker host
Cần cài thêm module wireguard nếu cần. Mình đang xài Alpine Virtual 3.22 cho cả host và container nên nó có sẵn module

Need to install additional wireguard module if needed. I'm using Alpine Virtual 3.22 for both host and container so it has the module available.

https://www.wireguard.com/install/
