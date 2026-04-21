# 🔐 OpenID Connect Security Demo

Một ứng dụng giáo dục về **OpenID Connect** để học tập các lỗ hổng bảo mật phổ biến và cách phòng chống chúng.

## 📋 Mô tả dự án

Dự án này minh họa:
- **Luồng xác thực OpenID Connect** (Authentication Flow)
- **Các cuộc tấn công phổ biến**: XSS, CSRF, Token Stealing, Phishing, Code Injection
- **Biện pháp phòng chống** an toàn cho từng loại tấn công
- **Hệ thống đánh giá bảo mật** (Security Score) để đo mức độ an toàn của ứng dụng

## 🚀 Cấu trúc dự án

```
OpenID/
├── index.html              # Trang chính - Ứng dụng client OpenID Connect
├── script.js               # Logic chính của ứng dụng
├── style.css               # Giao diện chính
├── README.md               # Tệp này
├── attacker/               # Thư mục demo các cuộc tấn công
│   ├── attacker-server.js  # Server giả mạo (port 5502)
│   ├── attacker.html       # Giao diện trang tấn công
│   ├── attacker.js         # Logic các cuộc tấn công
│   ├── attacker.css        # Giao diện tấn công
│   └── package.json        # Dependencies
└── Defend/                 # Thư mục hướng dẫn phòng chống
    ├── Defense Guide.html  # Hướng dẫn bảo mật với Security Score
    ├── Defense Guide.js    # Logic kiểm tra bảo mật
    └── Defense Guide.css   # Giao diện hướng dẫn
```

## 🎯 Tính năng chính

### 1. **Demo OpenID Connect Flow**
- Hiển thị quy trình xác thực 4 bước
- Minh họa các thành phần: Authorization Server, Client, ID Token, Access Token

### 2. **Các cuộc tấn công được demo**
- **XSS (Cross-Site Scripting)**: Inject mã JavaScript độc hại
- **CSRF (Cross-Site Request Forgery)**: Giả mạo yêu cầu từ người dùng
- **Token Stealing**: Đánh cắp các token xác thực
- **Phishing**: Giả mạo trang đăng nhập
- **Code Injection**: Chèn mã độc vào request

### 3. **Security Score System** 
Đánh giá bảo mật ứng dụng theo 6 tiêu chí:
- XSS Protection (20 điểm)
- CSRF Protection (15 điểm)
- Phishing Prevention (15 điểm)
- Token Security (25 điểm)
- Code Protection (15 điểm)
- Session Security (10 điểm)

## 🛠️ Cách sử dụng

### Chạy ứng dụng chính
1. Mở `index.html` bằng Live Server trên **port 5501**
2. Đăng nhập bằng email để thấy OpenID Connect flow

### Xem demo tấn công
1. Mở `attacker/attacker-server.js` và chạy server:
   ```bash
   cd attacker
   npm install
   node attacker-server.js
   ```
2. Mở `attacker/attacker.html` trên **port 5500**
3. Thực hiện các cuộc tấn công để thấy cách chúng hoạt động

### Kiểm tra bảo mật
1. Mở `Defend/Defense Guide.html`
2. Hệ thống sẽ tự động kiểm tra bảo mật của `index.html`
3. Xem điểm số và các khuyến nghị cải thiện

## 📖 Các lỗ hổng được học

### 1. **Token Exposure**
- Token không được bảo vệ khi lưu trữ
- Token có thể bị đánh cắp qua XSS

### 2. **CORS Misconfiguration**
- Cho phép request từ bất kỳ domain nào
- Attacker có thể truy cập tài nguyên từ domain khác

### 3. **Missing State Parameter**
- Không xác minh state để phòng chống CSRF
- Authorization code có thể bị lạm dụng

### 4. **Insecure Token Storage**
- Lưu token trong localStorage (dễ bị XSS)
- Không sử dụng HttpOnly cookies

### 5. **Phishing Vulnerability**
- Không xác minh authorization server
- Người dùng có thể bị dẫn đến trang giả mạo

## 🛡️ Các biện pháp phòng chống

1. **Sử dụng HttpOnly Cookies** cho token
2. **Implement CSRF Protection** bằng state parameter
3. **Content Security Policy (CSP)** để chống XSS
4. **CORS Configuration** chặt chẽ
5. **Token Validation** trên backend
6. **Secure Session Management**

## 👨‍💻 Công nghệ sử dụng

- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Backend**: Node.js + Express (cho attacker server)
- **CORS Management**: Cors middleware

## 📚 Tài liệu tham khảo

- [OpenID Connect Specifications](https://openid.net/connect/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

## ⚠️ Lưu ý bảo mật

**Dự án này chỉ dành cho mục đích giáo dục!** Không được sử dụng để tấn công các hệ thống khác.
