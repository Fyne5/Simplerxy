# Simplerxy
Simplerxy - Một proxy đơn giản dễ xài, thoát tục

Simplerxy - A simple, easy-to-use, lightweight proxy

## Mô tả / Describes
Simplerxy - Một proxy đơn giản dễ xài, thoát tục được viết bằng Golang với sự giúp sức của Gemini. Nhu cầu chính của Simplerxy là giúp vượt lọc chặn dựa vào SNI/DPI của nhà mạng. Quan trọng: Simplerxy không chèn, làm sai lệch, cũng như không thu thập thông tin mã hóa HTTPS.

Nhưng mà, nếu mấy nhà mạng chặn dựa vào IP, chỉ còn cách xài VPN hay proxy của nước ngoài.

Hỗ trợ các phương thức proxy: HTTP, HTTPS, SOCKS5 TCP, SOCKS5 UDP.

Simplerxy - A simple, easy-to-use, lightweight proxy is written in Golang with the help from Gemini. Simplerxy helps bypass SNI/DPI filters from ISPs. Important: Simplerxy does not insert, false, nor does not collect encryption information HTTPS.

However, if the ISPs blocks hard IPs, it is only possible to use VPN or proxy from abroad.

Support proxy's methods: HTTP, HTTPS, SOCKS5 TCP, SOCKS5 UDP.

## Cách biên dịch ra nhị phân / How to build to binary
```
git clone https://github.com/Fyne5/Simplerxy.git
cd Simplerxy
go build -o Simplerxy main.go
```
Bởi tui đang xài MacOS Intel nên khi biên dịch cơ bản, nó sẽ chỉ cho MacOS Intel. Muốn từ MacOS Intel biên dịch cho hệ khác thì

Because I'm using MacOS Intel, when compiling basically, it will only be for MacOS Intel. If you want to compile from MacOS Intel to another system, then
```
GOOS=darwin GOARCH=amd64 go build -o Simplerxy-macos-amd64 main.go
GOOS=darwin GOARCH=arm64 go build -o Simplerxy-macos-arm64 main.go
GOOS=linux GOARCH=amd64 go build -o Simplerxy-linux-amd64 main.go
GOOS=linux GOARCH=arm64 go build -o Simplerxy-linux-arm64 main.go
GOOS=linux GOARCH=386 go build -o Simplerxy-linux-386 main.go
GOOS=windows GOARCH=amd64 go build -o Simplerxy-win-amd64.exe main.go
GOOS=windows GOARCH=386 go build -o Simplerxy-win-386.exe main.go
```

## Cách xài / How to use
```
./Simplerxy
```

Khai báo trong proxy của hệ thống hoặc trình duyệt. Hay xài curl.

Declare in the proxy of the system or browser. Or use curl.

```
curl -I https://medium.com -x http://127.0.0.1:3979
HTTP/1.1 200 Connection established

HTTP/2 103
link: <https://glyph.medium.com/css/unbound.css>; as=style; rel=preload
```
![Screen Shot 2025-06-04 at 11 27 35](https://github.com/user-attachments/assets/add4af1b-b60c-4008-ad82-21c36f91a4b8)

## Tùy biến cấu hình / Customize configuration
Mặc định Simplerxy sẽ chạy ở cổng TCP 3979 (con số thần Tài trong Đề Số Học) và giao tiếp tại tất cả các địa chỉ (0.0.0.0). Có thể tùy chỉnh trong config.conf để cho phù hợp

By default Simplerxy will run at TCP 3979 (God of Fortune’s lucky number for lottery gamblers) and communicate at all addresses (0.0.0.0). Can be customized in config.conf to fit

## Docker docker-compose.yaml
Xem trong thư mục docker rồi kích chạy RUN.sh

Look in the docker folder and click RUN.sh

## Báo cáo của VirusTotal về phiên bản Windows / Windows version VirusTotal report
Cái này bình thường, ai không tin tưởng thì đem mã nguồn về tự biên dịch sẽ tự tin hơn.

This is normal. If you don't trust it, you can compile the source code yourself for peace of mind.

https://www.virustotal.com/gui/file/a24746e82c547005eadbaae81c0b04ed54b40b0d29c3d72644c2c403e60d6197
<img width="1823" height="777" alt="Windows VirusTotal" src="https://github.com/user-attachments/assets/3c41e36d-b912-4f51-a409-b3b7d73b3ff8" />

## Kết hợp ProxyBridge / Combining ProxyBridge
Có nhiều trình khởi chạy game như Steam sẽ tự kết nối riêng mà không xài proxy https/http của Windows, tụi nó chạy qua tcp/udp riêng biệt. Vì vậy cần ép tụi nó bằng trình quản lý session tầng 5. Miễn phí thì có ProxyBridge, WinSocks, ... Trả phí thì Proxifier, ...

Many game launchers like Steam connect on their own without using HTTPS/HTTP Windows's proxies, running through separate TCP/UDP protocols. Therefore, it is necessary to force them using a layer-5 session manager. Free options include ProxyBridge, WinSocks, etc. Paid options include Proxifier, etc.

<img width="1323" height="1198" alt="1 0 0" src="https://github.com/user-attachments/assets/b62fc6af-b3dc-430f-841b-9ed24580a7eb" />

