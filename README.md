# Simplerxy
Simplerxy - Một proxy đơn giản dễ xài, thoát tục

Simplerxy - A simple, easy-to-use, lightweight proxy

## Mô tả / Describes
Simplerxy - Một proxy đơn giản dễ xài, thoát tục được viết bằng Golang với sự giúp sức của Gemini. Nhu cầu chính của Simplerxy là giúp vượt lọc chặn dựa vào SNI/DPI của nhà mạng. Quan trọng: Simplerxy không chèn, làm sai lệch, cũng như không thu thập thông tin mã hóa HTTPS.

Nhưng mà, nếu mấy nhà mạng chặn dựa vào IP, chỉ còn các xài VPN hay proxy của nước ngoài.

Simplerxy - A simple, easy-to-use, lightweight proxy is written in Golang with the help from Gemini. The main purpose of Simplerxy simply helps to overcome the SNI/DPI filter of the carriers (ISPs). Important: Simplerxy does not insert, false, nor does not collect encryption information HTTPS.

However, if the ISPs blocks hard IPs, it is only possible to use VPN or proxy from abroad.

## Cách biên dịch ra nhị phân / How to build to binary
```
git clone https://github.com/Fyne5/Simplerxy.git
cd Simplerxy
go build -o simplerxy main.go
```

## Cách xài / How to use
```
./simplerxy
```

Khai báo trong proxy của hệ thống hoặc trình duyệt. Hay xài curl.

Declare in the proxy of the system or browser. Or use curl.

```
curl -I https://medium.com -x http://127.0.0.1:3979
HTTP/1.1 200 Connection established

HTTP/2 103
link: <https://glyph.medium.com/css/unbound.css>; as=style; rel=preload
```

## Tùy biến cấu hình / Customize configuration
Mặc định Simplerxy sẽ chạy ở cổng TCP 3979 (con số thần Tài trong Đề Số Học) và giao tiếp tại tất cả các địa chỉ (0.0.0.0). Có thể tùy chỉnh trong config.conf để cho phù hợp

By default Simplerxy will run at TCP 3979 (God of Fortune’s lucky number for lottery gamblers) and communicate at all addresses (0.0.0.0). Can be customized in config.conf to fit

## Docker bằng docker-compose.yaml / Docker with docker-compose.yaml
Đang cập nhựt...

Updating...