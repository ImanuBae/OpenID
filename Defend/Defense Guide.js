// defense.js

// Score tracking
let scores = {
    xss: 0,
    csrf: 0,
    phishing: 0,
    token: 0,
    code: 0,
    session: 0
};

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    loadProgress();
    updateScore();
    
    // Add event listeners to all checkboxes
    document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
        checkbox.addEventListener('change', handleCheckboxChange);
    });
});

// Handle checkbox changes
function handleCheckboxChange(event) {
    const checkbox = event.target;
    const defense = checkbox.dataset.defense;
    const points = parseInt(checkbox.dataset.points);
    
    if (checkbox.checked) {
        scores[defense] += points;
    } else {
        scores[defense] -= points;
    }
    
    updateScore();
    saveProgress();
}

// Update score display
function updateScore() {
    const totalScore = Object.values(scores).reduce((a, b) => a + b, 0);
    document.getElementById('scoreValue').textContent = totalScore;
    
    // Update individual scores
    document.getElementById('xssScore').textContent = `${scores.xss}/20`;
    document.getElementById('csrfScore').textContent = `${scores.csrf}/15`;
    document.getElementById('phishingScore').textContent = `${scores.phishing}/15`;
    document.getElementById('tokenScore').textContent = `${scores.token}/25`;
    document.getElementById('codeScore').textContent = `${scores.code}/15`;
    document.getElementById('sessionScore').textContent = `${scores.session}/10`;
    
    // Update status
    const statusEl = document.getElementById('scoreStatus');
    if (totalScore >= 80) {
        statusEl.textContent = 'Secure ✅';
        statusEl.className = 'score-status safe';
    } else if (totalScore >= 50) {
        statusEl.textContent = 'Moderate ⚠️';
        statusEl.className = 'score-status moderate';
    } else {
        statusEl.textContent = 'Vulnerable ❌';
        statusEl.className = 'score-status';
    }
}

// Save progress to localStorage
function saveProgress() {
    const checkboxes = {};
    document.querySelectorAll('input[type="checkbox"]').forEach((cb, index) => {
        checkboxes[index] = cb.checked;
    });
    localStorage.setItem('defenseProgress', JSON.stringify({ scores, checkboxes }));
}

// Load progress
function loadProgress() {
    const saved = localStorage.getItem('defenseProgress');
    if (saved) {
        const data = JSON.parse(saved);
        scores = data.scores;
        
        document.querySelectorAll('input[type="checkbox"]').forEach((cb, index) => {
            if (data.checkboxes[index]) {
                cb.checked = true;
            }
        });
    }
}

// Reset progress
function resetProgress() {
    if (confirm('Bạn có chắc muốn reset toàn bộ tiến trình?')) {
        scores = { xss: 0, csrf: 0, phishing: 0, token: 0, code: 0, session: 0 };
        document.querySelectorAll('input[type="checkbox"]').forEach(cb => {
            cb.checked = false;
        });
        updateScore();
        localStorage.removeItem('defenseProgress');
        alert('✅ Đã reset tiến trình!');
    }
}

// ========== DEFENSE GUIDES ==========

function showXSSDefense() {
    const content = `
        <h2>🛡️ XSS Protection Implementation</h2>
        
        <h3>1. Input Sanitization</h3>
        <div class="code-block"><code>// Server-side (Node.js)
const validator = require('validator');

function sanitizeInput(input) {
    return validator.escape(input);
}

app.post('/login', (req, res) => {
    const email = sanitizeInput(req.body.email);
    const name = sanitizeInput(req.body.name);
    // Process sanitized input
});</code></div>

        <h3>2. Content Security Policy (CSP)</h3>
        <div class="code-block"><code>// Server-side header
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; style-src 'self'"
    );
    next();
});</code></div>

        <h3>3. HttpOnly Cookies</h3>
        <div class="code-block"><code>// Set cookie with httpOnly flag
res.cookie('session', token, {
    httpOnly: true,  // Không thể access bằng JavaScript
    secure: true,    // Chỉ gửi qua HTTPS
    sameSite: 'strict'
});</code></div>

        <h3>4. Output Encoding</h3>
        <div class="code-block"><code>// Client-side
function displayUserName(name) {
    const div = document.createElement('div');
    div.textContent = name; // Tự động escape
    // KHÔNG dùng: div.innerHTML = name; ❌
    return div;
}</code></div>

        <h3>✅ Checklist</h3>
        <ul>
            <li>✓ Validate tất cả user input</li>
            <li>✓ Escape output khi render</li>
            <li>✓ Implement CSP headers</li>
            <li>✓ Use httpOnly cookies</li>
            <li>✓ Avoid innerHTML, use textContent</li>
            <li>✓ Regular security audits</li>
        </ul>
    `;
    
    showModal(content);
}

function showCSRFDefense() {
    const content = `
        <h2>🛡️ CSRF Protection Implementation</h2>
        
        <h3>1. CSRF Tokens</h3>
        <div class="code-block"><code>// Server-side (Express + csurf)
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.get('/form', csrfProtection, (req, res) => {
    res.render('form', { csrfToken: req.csrfToken() });
});

app.post('/submit', csrfProtection, (req, res) => {
    // Token tự động validate
    res.send('Success!');
});</code></div>

        <h3>2. Client-side Token Usage</h3>
        <div class="code-block"><code><!-- HTML Form -->
&lt;form method="POST" action="/submit"&gt;
    &lt;input type="hidden" name="_csrf" value="{{ csrfToken }}"&gt;
    &lt;!-- Other fields --&gt;
&lt;/form&gt;

// AJAX Request
fetch('/api/endpoint', {
    method: 'POST',
    headers: {
        'CSRF-Token': csrfToken,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
});</code></div>

        <h3>3. SameSite Cookies</h3>
        <div class="code-block"><code>res.cookie('sessionId', token, {
    sameSite: 'strict',  // Không gửi trong cross-site requests
    secure: true,
    httpOnly: true
});</code></div>

        <h3>4. Origin/Referer Validation</h3>
        <div class="code-block"><code>function validateOrigin(req, res, next) {
    const origin = req.get('origin');
    const allowedOrigins = ['https://myapp.com'];
    
    if (!origin || !allowedOrigins.includes(origin)) {
        return res.status(403).send('Forbidden');
    }
    next();
}</code></div>

        <h3>✅ Checklist</h3>
        <ul>
            <li>✓ Implement CSRF tokens cho state-changing requests</li>
            <li>✓ Use SameSite cookies</li>
            <li>✓ Validate Origin/Referer headers</li>
            <li>✓ Require re-authentication cho sensitive actions</li>
        </ul>
    `;
    
    showModal(content);
}

function showPhishingDefense() {
    const content = `
        <h2>🛡️ Phishing Prevention</h2>
        
        <h3>1. HTTPS Everywhere</h3>
        <div class="code-block"><code>// Force HTTPS redirect
app.use((req, res, next) => {
    if (!req.secure && req.get('x-forwarded-proto') !== 'https') {
        return res.redirect('https://' + req.get('host') + req.url);
    }
    next();
});

// HSTS Header
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 
        'max-age=31536000; includeSubDomains; preload');
    next();
});</code></div>

        <h3>2. Multi-Factor Authentication</h3>
        <div class="code-block"><code>// TOTP Implementation
const speakeasy = require('speakeasy');

// Generate secret
const secret = speakeasy.generateSecret();

// Verify token
const verified = speakeasy.totp.verify({
    secret: userSecret,
    encoding: 'base32',
    token: userToken
});</code></div>

        <h3>3. FIDO2/WebAuthn (Phishing-Resistant)</h3>
        <div class="code-block"><code>// Client-side WebAuthn
const credential = await navigator.credentials.create({
    publicKey: {
        challenge: new Uint8Array(32),
        rp: { name: "My App" },
        user: {
            id: userId,
            name: email,
            displayName: name
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
    }
});

// Send to server for storage</code></div>

        <h3>4. Security Awareness</h3>
        <ul>
            <li>✓ Train users to check URL trước khi login</li>
            <li>✓ Look for HTTPS và valid certificate</li>
            <li>✓ Không click suspicious links</li>
            <li>✓ Use password managers (auto-detect phishing)</li>
            <li>✓ Report phishing attempts</li>
        </ul>

        <h3>5. Technical Controls</h3>
        <ul>
            <li>✓ Implement email verification</li>
            <li>✓ Device recognition</li>
            <li>✓ Anomaly detection (unusual login location)</li>
            <li>✓ Browser phishing protection</li>
        </ul>
    `;
    
    showModal(content);
}

function showTokenDefense() {
    const content = `
        <h2>🛡️ Token Security Implementation</h2>
        
        <h3>1. Short Token Lifetime</h3>
        <div class="code-block"><code>// JWT Generation
const jwt = require('jsonwebtoken');

const accessToken = jwt.sign(
    { userId: user.id },
    SECRET_KEY,
    { expiresIn: '15m' }  // Short lifetime
);

const refreshToken = jwt.sign(
    { userId: user.id },
    REFRESH_SECRET,
    { expiresIn: '7d' }
);</code></div>

        <h3>2. Token Binding</h3>
        <div class="code-block"><code>// Include device fingerprint in token
const deviceFingerprint = generateFingerprint(req);

const token = jwt.sign({
    userId: user.id,
    deviceId: deviceFingerprint,
    ip: req.ip
}, SECRET_KEY);

// Validate on each request
function validateToken(req, res, next) {
    const token = getTokenFromRequest(req);
    const decoded = jwt.verify(token, SECRET_KEY);
    
    const currentFingerprint = generateFingerprint(req);
    if (decoded.deviceId !== currentFingerprint) {
        return res.status(401).send('Invalid token binding');
    }
    
    next();
}</code></div>

        <h3>3. Refresh Token Rotation</h3>
        <div class="code-block"><code>app.post('/refresh', async (req, res) => {
    const oldRefreshToken = req.body.refreshToken;
    
    try {
        const decoded = jwt.verify(oldRefreshToken, REFRESH_SECRET);
        
        // Check if token was already used
        if (await isTokenRevoked(oldRefreshToken)) {
            // Possible replay attack - revoke all tokens
            await revokeAllUserTokens(decoded.userId);
            return res.status(403).send('Token reuse detected');
        }
        
        // Revoke old token
        await revokeToken(oldRefreshToken);
        
        // Issue new tokens
        const newAccessToken = generateAccessToken(decoded.userId);
        const newRefreshToken = generateRefreshToken(decoded.userId);
        
        res.json({ 
            accessToken: newAccessToken,
            refreshToken: newRefreshToken 
        });
    } catch (err) {
        res.status(401).send('Invalid refresh token');
    }
});</code></div>

        <h3>4. JWT Validation</h3>
        <div class="code-block"><code>function validateJWT(token) {
    try {
        const decoded = jwt.verify(token, SECRET_KEY, {
            algorithms: ['RS256'],  // Only allow secure algorithms
            issuer: 'https://myapp.com',
            audience: 'api.myapp.com'
        });
        
        // Additional checks
        if (!decoded.jti || !decoded.sub) {
            throw new Error('Missing required claims');
        }
        
        // Check against revocation list
        if (isRevoked(decoded.jti)) {
            throw new Error('Token revoked');
        }
        
        return decoded;
    } catch (err) {
        throw new Error('Invalid token');
    }
}</code></div>

        <h3>5. Anomaly Detection</h3>
        <div class="code-block"><code>async function detectAnomalies(userId, req) {
    const currentLocation = getLocation(req.ip);
    const lastLocation = await getLastLoginLocation(userId);
    
    // Impossible travel detection
    const distance = calculateDistance(currentLocation, lastLocation);
    const timeDiff = Date.now() - lastLocation.timestamp;
    const maxSpeed = 1000; // km/h
    
    if (distance / timeDiff > maxSpeed) {
        await sendSecurityAlert(userId, 'Impossible travel detected');
        return true;
    }
    
    return false;
}</code></div>

        <h3>✅ Best Practices</h3>
        <ul>
            <li>✓ Access tokens: 5-15 minutes</li>
            <li>✓ Refresh tokens: 7-30 days with rotation</li>
            <li>✓ Use jti claim for revocation</li>
            <li>✓ Implement token blacklist</li>
            <li>✓ Monitor unusual token usage</li>
            <li>✓ Log all token operations</li>
        </ul>
    `;
    
    showModal(content);
}

function showCodeDefense() {
    const content = `
        <h2>🛡️ Authorization Code Protection</h2>
        
        <h3>1. PKCE Implementation (RFC 7636)</h3>
        <div class="code-block"><code>// Client-side: Generate code verifier
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
}

// Generate code challenge
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return base64URLEncode(new Uint8Array(hash));
}

// Authorization request
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Store verifier for later use
sessionStorage.setItem('code_verifier', codeVerifier);

// Redirect to authorization endpoint
window.location.href = \`\${authEndpoint}?
    client_id=\${clientId}&
    redirect_uri=\${redirectUri}&
    code_challenge=\${codeChallenge}&
    code_challenge_method=S256&
    response_type=code\`;</code></div>

        <h3>2. Server-side PKCE Validation</h3>
        <div class="code-block"><code>// Authorization endpoint
app.get('/authorize', (req, res) => {
    const { code_challenge, code_challenge_method } = req.query;
    
    // Store challenge with authorization code
    const authCode = generateAuthCode();
    storeCodeChallenge(authCode, code_challenge, code_challenge_method);
    
    res.redirect(\`\${redirectUri}?code=\${authCode}\`);
});

// Token endpoint
app.post('/token', async (req, res) => {
    const { code, code_verifier } = req.body;
    
    // Retrieve stored challenge
    const storedChallenge = await getCodeChallenge(code);
    
    // Validate verifier
    const computedChallenge = sha256(code_verifier);
    
    if (computedChallenge !== storedChallenge.challenge) {
        return res.status(400).json({ error: 'invalid_grant' });
    }
    
    // Issue tokens
    const tokens = generateTokens();
    res.json(tokens);
});</code></div>

        <h3>3. Redirect URI Whitelist</h3>
        <div class="code-block"><code>const clientConfig = {
    'client_123': {
        redirectUris: [
            'https://myapp.com/callback',
            'https://myapp.com/auth/callback'
        ]
    }
};

function validateRedirectUri(clientId, redirectUri) {
    const client = clientConfig[clientId];
    
    if (!client) {
        return false;
    }
    
    // Exact match only (no startsWith)
    return client.redirectUris.includes(redirectUri);
}

app.get('/authorize', (req, res) => {
    const { client_id, redirect_uri } = req.query;
    
    if (!validateRedirectUri(client_id, redirect_uri)) {
        return res.status(400).send('Invalid redirect_uri');
    }
    
    // Continue authorization
});</code></div>

        <h3>4. One-Time Code Usage</h3>
        <div class="code-block"><code>const usedCodes = new Set();

app.post('/token', async (req, res) => {
    const { code } = req.body;
    
    // Check if code already used
    if (usedCodes.has(code)) {
        // Revoke all tokens for this user
        await revokeAllTokens(code);
        return res.status(400).json({ 
            error: 'Code reuse detected - all tokens revoked' 
        });
    }
    
    // Mark code as used
    usedCodes.add(code);
    
    // Set expiration (5 minutes)
    setTimeout(() => usedCodes.delete(code), 5 * 60 * 1000);
    
    // Issue tokens
    const tokens = generateTokens();
    res.json(tokens);
});</code></div>

        <h3>✅ Security Checklist</h3>
        <ul>
            <li>✓ Always use PKCE (even for confidential clients)</li>
            <li>✓ Strict redirect URI validation (exact match)</li>
            <li>✓ Short code lifetime (1-5 minutes)</li>
            <li>✓ One-time code usage only</li>
            <li>✓ Use state parameter (CSRF protection)</li>
            <li>✓ Validate client_id</li>
            <li>✓ Log all authorization attempts</li>
        </ul>
    `;
    
    showModal(content);
}

function showSessionDefense() {
    const content = `
        <h2>🛡️ Session Security Implementation</h2>
        
        <h3>1. Device Fingerprinting</h3>
        <div class="code-block"><code>// Client-side fingerprinting
async function generateFingerprint() {
    const components = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        screenResolution: \`\${screen.width}x\${screen.height}\`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        canvas: await getCanvasFingerprint()
    };
    
    const fingerprintString = JSON.stringify(components);
    const encoder = new TextEncoder();
    const data = encoder.encode(fingerprintString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getCanvasFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Browser fingerprint', 2, 2);
    return canvas.toDataURL();
}</code></div>

        <h3>2. IP Validation</h3>
        <div class="code-block"><code>function validateIPAddress(req, res, next) {
    const token = getTokenFromRequest(req);
    const decoded = jwt.verify(token, SECRET_KEY);
    
    const currentIP = req.ip;
    const tokenIP = decoded.ip;
    
    if (currentIP !== tokenIP) {
        // Log suspicious activity
        logSecurityEvent({
            type: 'ip_mismatch',
            userId: decoded.userId,
            tokenIP,
            currentIP
        });
        
        // Require re-authentication
        return res.status(401).json({
            error: 'IP address changed',
            requireReauth: true
        });
    }
    
    next();
}</code></div>

        <h3>3. Session Monitoring</h3>
        <div class="code-block"><code>// Track active sessions
const activeSessions = new Map();

function createSession(userId, deviceInfo) {
    const sessionId = generateSessionId();
    const session = {
        sessionId,
        userId,
        deviceInfo,
        createdAt: Date.now(),
        lastActivity: Date.now(),
        location: deviceInfo.location
    };
    
    activeSessions.set(sessionId, session);
    return sessionId;
}

// API: Get user's active sessions
app.get('/api/sessions', authenticate, (req, res) => {
    const userSessions = Array.from(activeSessions.values())
        .filter(s => s.userId === req.userId);
    
    res.json(userSessions);
});

// API: Revoke session
app.delete('/api/sessions/:sessionId', authenticate, (req, res) => {
    const sessionId = req.params.sessionId;
    const session = activeSessions.get(sessionId);
    
    if (session && session.userId === req.userId) {
        activeSessions.delete(sessionId);
        revokeSessionTokens(sessionId);
        res.json({ message: 'Session revoked' });
    } else {
        res.status(404).json({ error: 'Session not found' });
    }
});</code></div>

        <h3>4. Anomaly Detection</h3>
        <div class="code-block"><code>async function detectSessionAnomaly(userId, req) {
    const anomalies = [];
    
    // Check 1: Impossible travel
    const currentLocation = await getLocation(req.ip);
    const lastLocation = await getLastActivityLocation(userId);
    
    if (isImpossibleTravel(currentLocation, lastLocation)) {
        anomalies.push('impossible_travel');
    }
    
    // Check 2: Device change
    const currentDevice = generateFingerprint(req);
    const knownDevices = await getKnownDevices(userId);
    
    if (!knownDevices.includes(currentDevice)) {
        anomalies.push('unknown_device');
    }
    
    // Check 3: Unusual time
    const currentHour = new Date().getHours();
    const typicalHours = await getTypicalActivityHours(userId);
    
    if (!typicalHours.includes(currentHour)) {
        anomalies.push('unusual_time');
    }
    
    // Check 4: Multiple concurrent sessions
    const sessionCount = await getActiveSessionCount(userId);
    if (sessionCount > 5) {
        anomalies.push('too_many_sessions');
    }
    
    if (anomalies.length > 0) {
        await sendSecurityAlert(userId, anomalies);
        await requireStepUpAuth(userId);
    }
    
    return anomalies;
}</code></div>

        <h3>✅ Best Practices</h3>
        <ul>
            <li>✓ Bind sessions to device fingerprint</li>
            <li>✓ Validate IP address on each request</li>
            <li>✓ Monitor and log all session activities</li>
            <li>✓ Allow users to view/revoke active sessions</li>
            <li>✓ Implement anomaly detection</li>
            <li>✓ Session timeout (absolute + idle)</li>
            <li>✓ Require re-auth for sensitive actions</li>
        </ul>
    `;
    
    showModal(content);
}

// Modal functions
function showModal(content) {
    const modal = document.getElementById('guideModal');
    document.getElementById('guideContent').innerHTML = content;
    modal.style.display = 'block';
}

function closeModal() {
    document.getElementById('guideModal').style.display = 'none';
}

// Implementation functions
function implementXSSDefense() {
    alert('🔧 Implementing XSS Protection...\n\n' +
          'Bước 1: Install dependencies\n' +
          'npm install validator dompurify\n\n' +
          'Bước 2: Configure CSP headers\n' +
          'Bước 3: Update cookie settings\n' +
          'Bước 4: Sanitize all inputs\n\n' +
          'Click "Xem Hướng Dẫn" để xem code chi tiết!');
}

function implementCSRFDefense() {
    alert('🔧 Implementing CSRF Protection...\n\n' +
          'Bước 1: Install csurf middleware\n' +
          'npm install csurf\n\n' +
          'Bước 2: Configure CSRF tokens\n' +
          'Bước 3: Update forms\n' +
          'Bước 4: Add SameSite cookies\n\n' +
          'Click "Xem Hướng Dẫn" để xem code chi tiết!');
}

function implementPhishingDefense() {
    alert('🔧 Implementing Phishing Prevention...\n\n' +
          'Bước 1: Setup HTTPS\n' +
          'Bước 2: Implement MFA\n' +
          'npm install speakeasy qrcode\n\n' +
          'Bước 3: Add WebAuthn support\n' +
          'Bước 4: User education program\n\n' +
          'Click "Xem Hướng Dẫn" để xem code chi tiết!');
}

function implementTokenDefense() {
    alert('🔧 Implementing Token Security...\n\n' +
          'Bước 1: Shorten token lifetime\n' +
          'Bước 2: Implement token binding\n' +
          'Bước 3: Setup refresh rotation\n' +
          'Bước 4: Add anomaly detection\n\n' +
          'Click "Xem Hướng Dẫn" để xem code chi tiết!');
}

function implementCodeDefense() {
    alert('🔧 Implementing Code Protection...\n\n' +
          'Bước 1: Implement PKCE\n' +
          'Bước 2: Strict redirect URI validation\n' +
          'Bước 3: One-time code usage\n' +
          'Bước 4: Short code lifetime\n\n' +
          'Click "Xem Hướng Dẫn" để xem code chi tiết!');
}

function implementSessionDefense() {
    alert('🔧 Implementing Session Security...\n\n' +
          'Bước 1: Device fingerprinting\n' +
          'Bước 2: IP validation\n' +
          'Bước 3: Session monitoring\n' +
          'Bước 4: Anomaly detection\n\n' +
          'Click "Xem Hướng Dẫn" để xem code chi tiết!');
}

// Download checklist
function downloadSecurityChecklist() {
    const checklist = `
OPENID CONNECT SECURITY CHECKLIST
==================================

[ ] XSS Protection (20 points)
    [ ] Input sanitization (5)
    [ ] Content Security Policy (5)
    [ ] HttpOnly cookies (5)
    [ ] Output encoding (5)

[ ] CSRF Protection (15 points)
    [ ] CSRF tokens (5)
    [ ] SameSite cookies (5)
    [ ] Origin validation (5)

[ ] Phishing Prevention (15 points)
    [ ] HTTPS everywhere (4)
    [ ] Multi-factor auth (4)
    [ ] Security awareness (4)
    [ ] FIDO2/WebAuthn (3)

[ ] Token Security (25 points)
    [ ] Short lifetime (5)
    [ ] Token binding (5)
    [ ] Refresh rotation (5)
    [ ] JWT validation (5)
    [ ] Anomaly detection (5)

[ ] Code Protection (15 points)
    [ ] PKCE implementation (5)
    [ ] Redirect URI whitelist (5)
    [ ] One-time usage (5)

[ ] Session Security (10 points)
    [ ] Device fingerprinting (3)
    [ ] IP validation (3)
    [ ] Session monitoring (4)

TOTAL: /100 points
Target: 80+ points for "Secure" status
    `;
    
    const blob = new Blob([checklist], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'security-checklist.txt';
    a.click();
    URL.revokeObjectURL(url);
    
    alert('✅ Security checklist downloaded!');
}

// Generate report
function generateReport() {
    const totalScore = Object.values(scores).reduce((a, b) => a + b, 0);
    const date = new Date().toLocaleDateString('vi-VN');
    
    const report = `
╔════════════════════════════════════════════════════════════╗
║          SECURITY ASSESSMENT REPORT                        ║
║          OpenID Connect Implementation                     ║
╚════════════════════════════════════════════════════════════╝

Date: ${date}
Overall Security Score: ${totalScore}/100

SCORE BREAKDOWN:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. XSS Protection:          ${scores.xss}/20   ${getScoreBar(scores.xss, 20)}
2. CSRF Protection:         ${scores.csrf}/15   ${getScoreBar(scores.csrf, 15)}
3. Phishing Prevention:     ${scores.phishing}/15   ${getScoreBar(scores.phishing, 15)}
4. Token Security:          ${scores.token}/25   ${getScoreBar(scores.token, 25)}
5. Code Protection:         ${scores.code}/15   ${getScoreBar(scores.code, 15)}
6. Session Security:        ${scores.session}/10   ${getScoreBar(scores.session, 10)}

OVERALL STATUS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${getOverallStatus(totalScore)}

RECOMMENDATIONS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${getRecommendations()}

NEXT STEPS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Complete all unchecked security measures
2. Implement code examples from defense guides
3. Conduct penetration testing
4. Setup continuous monitoring
5. Regular security audits
6. Keep dependencies updated
7. Security awareness training for team

COMPLIANCE CHECKLIST:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[ ] OWASP Top 10 addressed
[ ] OAuth 2.0 Security Best Practices (RFC 8252)
[ ] PKCE for OAuth Public Clients (RFC 7636)
[ ] OpenID Connect Core 1.0
[ ] GDPR compliance (if applicable)
[ ] PCI DSS (if handling payments)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Report generated by Security Defense Guide
For support: https://github.com/yourusername/security-guide
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    `;
    
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    
    alert('📊 Security report generated and downloaded!');
}

function getScoreBar(score, max) {
    const percentage = (score / max) * 100;
    const filled = Math.round(percentage / 10);
    const empty = 10 - filled;
    return '[' + '█'.repeat(filled) + '░'.repeat(empty) + '] ' + Math.round(percentage) + '%';
}

function getOverallStatus(score) {
    if (score >= 80) {
        return `✅ SECURE (${score}/100)
Your implementation has strong security measures in place.
Continue monitoring and maintaining these protections.`;
    } else if (score >= 50) {
        return `⚠️ MODERATE (${score}/100)
Your implementation has basic security but needs improvement.
Focus on addressing the missing security measures.`;
    } else {
        return `❌ VULNERABLE (${score}/100)
Your implementation has significant security gaps.
URGENT: Implement missing security measures immediately!`;
    }
}

function getRecommendations() {
    const recommendations = [];
    
    if (scores.xss < 20) {
        recommendations.push('• HIGH PRIORITY: Implement XSS protection (Input sanitization, CSP, HttpOnly cookies)');
    }
    if (scores.token < 25) {
        recommendations.push('• HIGH PRIORITY: Improve token security (Short lifetime, binding, rotation)');
    }
    if (scores.code < 15) {
        recommendations.push('• HIGH PRIORITY: Implement PKCE and strict redirect URI validation');
    }
    if (scores.csrf < 15) {
        recommendations.push('• MEDIUM PRIORITY: Add CSRF protection (Tokens, SameSite cookies)');
    }
    if (scores.phishing < 15) {
        recommendations.push('• MEDIUM PRIORITY: Enhance phishing prevention (MFA, WebAuthn)');
    }
    if (scores.session < 10) {
        recommendations.push('• MEDIUM PRIORITY: Strengthen session security (Fingerprinting, monitoring)');
    }
    
    if (recommendations.length === 0) {
        return '✅ All security measures implemented! Maintain and monitor continuously.';
    }
    
    return recommendations.join('\n');
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('guideModal');
    if (event.target == modal) {
        modal.style.display = 'none';
    }
}