// Simulated OpenID Connect data
let currentUser = null;
let tokens = null;

// Handle login form submission
function handleLogin(event) {
    event.preventDefault(); // Prevent form from submitting normally
    
    // Get form values
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const fullname = document.getElementById('fullname').value;
    
    // Validate form
    if (!email || !password || !fullname) {
        showError("Vui lòng điền đầy đủ thông tin!");
        return;
    }
    
    // Start login process with user data
    simulateLogin(email, fullname);
}

// Simulate the OpenID Connect authentication flow
async function simulateLogin(userEmail, userName) {
    const loginBtn = document.querySelector('#loginForm .btn-primary');
    const loginText = document.getElementById('loginText');
    const loginLoader = document.getElementById('loginLoader');
    
    // Show loading state
    loginText.classList.add('hidden');
    loginLoader.classList.remove('hidden');
    loginBtn.disabled = true;

    try {
        // Step 1: Authorization Request (simulate redirect to IdP)
        await simulateStep("Đang chuyển hướng đến Authorization Server...", 1000);
        
        // Step 2: User Authentication (simulate user login)
        await simulateStep("Đang xác thực người dùng...", 1500);
        
        // Step 3: Authorization Code (simulate callback)
        await simulateStep("Nhận authorization code...", 1000);
        
        // Step 4: Token Exchange
        await simulateStep("Đổi code lấy tokens...", 1200);
        
        // Generate mock tokens and user data with provided info
        generateMockTokens(userEmail, userName);
        generateMockUser(userEmail, userName);
        
        // Show user section
        document.getElementById('loginSection').classList.add('hidden');
        document.getElementById('userSection').classList.remove('hidden');
        
        // Populate user info
        populateUserInfo();
        
    } catch (error) {
        showError("Đăng nhập thất bại: " + error.message);
    } finally {
        // Reset button state
        loginText.classList.remove('hidden');
        loginLoader.classList.add('hidden');
        loginBtn.disabled = false;
    }
}

function simulateStep(message, delay) {
    return new Promise((resolve) => {
        console.log(message);
        setTimeout(resolve, delay);
    });
}

function generateMockTokens(userEmail, userName) {
    const now = Math.floor(Date.now() / 1000);
    const userId = "user" + Math.random().toString(36).substr(2, 9);
    
    // Mock JWT-like tokens (simplified for demo)
    tokens = {
        id_token: generateMockJWT({
            iss: "https://demo-idp.example.com",
            aud: "demo-client-id",
            sub: userId,
            email: userEmail,
            name: userName,
            iat: now,
            exp: now + 3600
        }),
        access_token: generateRandomToken(32),
        refresh_token: generateRandomToken(32),
        token_type: "Bearer",
        expires_in: 3600
    };
}

function generateMockUser(userEmail, userName) {
    const userId = "user" + Math.random().toString(36).substr(2, 9);
    
    currentUser = {
        id: userId,
        email: userEmail,
        name: userName,
        iss: "https://demo-idp.example.com",
        aud: "demo-client-id",
        exp: new Date(Date.now() + 3600000).toLocaleString('vi-VN')
    };
}

function generateMockJWT(payload) {
    // This is a simplified JWT for demo purposes
    const header = btoa(JSON.stringify({typ: "JWT", alg: "RS256"}));
    const payloadStr = btoa(JSON.stringify(payload));
    const signature = generateRandomToken(16);
    return `${header}.${payloadStr}.${signature}`;
}

function generateRandomToken(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

function populateUserInfo() {
    if (currentUser) {
        document.getElementById('userId').textContent = currentUser.id;
        document.getElementById('userEmail').textContent = currentUser.email;
        document.getElementById('userName').textContent = currentUser.name;
        document.getElementById('userIss').textContent = currentUser.iss;
        document.getElementById('userAud').textContent = currentUser.aud;
        document.getElementById('userExp').textContent = currentUser.exp;
    }
}

function showTokenInfo() {
    document.getElementById('loginSection').classList.add('hidden');
    document.getElementById('tokenSection').classList.remove('hidden');
    
    if (tokens) {
        document.getElementById('idTokenDisplay').textContent = 
            tokens.id_token.substring(0, 50) + '...';
        document.getElementById('accessTokenDisplay').textContent = 
            tokens.access_token.substring(0, 20) + '...';
        document.getElementById('refreshTokenDisplay').textContent = 
            tokens.refresh_token.substring(0, 20) + '...';
    }
}

function showTokenDetails() {
    if (tokens) {
        alert(`ID Token (first 100 chars):\n${tokens.id_token.substring(0, 100)}...\n\nAccess Token:\n${tokens.access_token}\n\nRefresh Token:\n${tokens.refresh_token}`);
    }
}

function backToLogin() {
    document.getElementById('tokenSection').classList.add('hidden');
    document.getElementById('loginSection').classList.remove('hidden');
}

function logout() {
    // Clear tokens and user data
    currentUser = null;
    tokens = null;
    
    // Reset form
    document.getElementById('loginForm').reset();
    
    // Show login section
    document.getElementById('userSection').classList.add('hidden');
    document.getElementById('loginSection').classList.remove('hidden');
    
    // Show success message
    showSuccess("Đăng xuất thành công!");
}

function showSuccess(message) {
    const alert = document.createElement('div');
    alert.className = 'alert alert-success';
    alert.textContent = message;
    document.querySelector('.container').prepend(alert);
    
    setTimeout(() => {
        alert.remove();
    }, 3000);
}

function showError(message) {
    const alert = document.createElement('div');
    alert.className = 'alert alert-error';
    alert.textContent = message;
    document.querySelector('.container').prepend(alert);
    
    setTimeout(() => {
        alert.remove();
    }, 5000);
}