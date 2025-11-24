const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const port = 3000;
const saltRounds = 10; 

// Koneksi ke database MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'faqihMysql', // GANTI DENGAN PASSWORD ANDA!
    database: 'api_db',      // Pastikan database sudah dibuat
    port: 3307               // GANTI DENGAN PORT MYSQL ANDA! (Default 3306)
});

// Cek koneksi database
db.connect((err) => {
    if (err) {
        console.error('Koneksi database gagal:', err);
    } else {
        console.log('Terhubung ke database MySQL (api_db)');
    }
});

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Konfigurasi Session
app.use(session({
    secret: 'secret-key-yang-sangat-rahasia', 
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 * 24 } // Session 24 jam
}));

// --- Helper Functions ---

/**
 * Menghitung status kunci berdasarkan tanggal kadaluarsa.
 * @param {string} expiryDate - Tanggal kadaluarsa dari database (UTC string).
 * @returns {'ON' | 'OFF'}
 */
function checkKeyStatus(expiryDate) {
    if (!expiryDate) return 'OFF';
    const now = new Date();
    const expiry = new Date(expiryDate);
    // Tambahkan 1 hari (86400000 ms) agar kunci masih aktif di hari kadaluarsa penuh
    return (expiry.getTime() + 86400000) > now.getTime() ? 'ON' : 'OFF';
}

// Fungsi generate API Key
function generateApiKey() {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let apiKey = '';
    const segments = [8, 4, 4, 4, 12];

    segments.forEach((segmentLength, index) => {
        for (let i = 0; i < segmentLength; i++) {
            apiKey += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        if (index < segments.length - 1) apiKey += '-';
    });
    return apiKey;
}

// --- Middlewares ---

// Middleware untuk cek apakah admin sudah login
function isAuthenticated(req, res, next) {
    if (req.session.isAdmin) {
        next();
    } else {
        res.redirect('/admin/login');
    }
}

/**
 * Middleware untuk otentikasi API Key (melindungi endpoint data).
 */
function apiAuthMiddleware(req, res, next) {
    const apiKey = req.headers['x-api-key'] || req.query.api_key;

    if (!apiKey) {
        return res.status(401).json({ 
            success: false, 
            message: 'Akses Ditolak: API Key tidak ditemukan. Harap sertakan kunci di header X-API-Key atau sebagai query parameter api_key.' 
        });
    }

    const query = 'SELECT expiry_date FROM masuk_api WHERE api_key = ?';
    db.query(query, [apiKey], (err, keys) => {
        if (err) {
            console.error('Error database saat otentikasi API Key:', err);
            return res.status(500).json({ success: false, message: 'Kesalahan Server Internal.' });
        }

        if (keys.length === 0) {
            return res.status(403).json({ success: false, message: 'Akses Ditolak: API Key tidak valid.' });
        }

        const key = keys[0];
        const status = checkKeyStatus(key.expiry_date);

        if (status === 'OFF') {
            return res.status(403).json({ success: false, message: 'Akses Ditolak: API Key telah kadaluarsa.' });
        }

        // Kunci valid dan aktif, lanjutkan
        req.apiKey = apiKey;
        next();
    });
}

// --- Frontend Routes ---

// Route halaman utama (menggunakan index.html)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// --- API Key Generation & User Registration ---

app.post('/generate-api-key', async (req, res) => {
    const { firstName, lastName, email, apiName } = req.body;

    if (!firstName || !lastName || !email || !apiName) {
        return res.status(400).json({
            success: false,
            message: 'Semua kolom harus diisi.'
        });
    }

    // 1. Cek apakah user sudah ada berdasarkan email
    const findUserQuery = 'SELECT id FROM user WHERE email = ?';
    db.query(findUserQuery, [email], (err, users) => {
        if (err) {
            console.error('Error saat mencari user:', err);
            return res.status(500).json({ success: false, message: 'Kesalahan database saat mencari user.' });
        }

        let userId;

        if (users.length > 0) {
            // User sudah ada
            userId = users[0].id;
            saveApiKey(userId, apiName, res);
        } else {
            // User belum ada, simpan data user baru
            const insertUserQuery = 'INSERT INTO user (first_name, last_name, email) VALUES (?, ?, ?)';
            db.query(insertUserQuery, [firstName, lastName, email], (err, result) => {
                if (err) {
                    console.error('Gagal menyimpan user baru:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'Gagal menyimpan data user ke database',
                        error: err.sqlMessage
                    });
                }
                userId = result.insertId;
                saveApiKey(userId, apiName, res);
            });
        }
    });
});

function saveApiKey(userId, apiName, res) {
    const apiKey = generateApiKey();
    // Set kadaluarsa 1 tahun dari sekarang (MySQL menangani waktu secara otomatis)
    const expiryDate = new Date();
    expiryDate.setFullYear(expiryDate.getFullYear() + 1);

    const query = 'INSERT INTO masuk_api (user_id, api_name, api_key, expiry_date) VALUES (?, ?, ?, ?)';
    db.query(query, [userId, apiName, apiKey, expiryDate], (err, result) => {
        if (err) {
            console.error('Gagal menyimpan API Key:', err);
            return res.status(500).json({
                success: false,
                message: 'Gagal menyimpan API Key ke database',
                error: err.sqlMessage
            });
        }
        res.status(201).json({
            success: true,
            apiName: apiName,
            apiKey: apiKey,
            userId: userId,
            insertedId: result.insertId,
            message: '✅ API Key berhasil dibuat.'
        });
    });
}

// --- Admin Authentication Routes ---

app.get('/admin/login', (req, res) => {
    if (req.session.isAdmin) return res.redirect('/admin/dashboard');
    res.send(getAdminLoginForm());
});

app.get('/admin/register', (req, res) => {
    if (req.session.isAdmin) return res.redirect('/admin/dashboard');
    res.send(getAdminRegisterForm());
});

app.post('/admin/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send('Email dan password wajib diisi!');

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const query = 'INSERT INTO admin (email, password) VALUES (?, ?)';
        db.query(query, [email, hashedPassword], (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.status(409).send('Email sudah terdaftar.');
                console.error('Gagal registrasi admin:', err);
                return res.status(500).send('Gagal menyimpan admin ke database.');
            }
            res.send(getSuccessMessage('Registrasi Admin berhasil!', '<a href="/admin/login">Login sekarang</a>'));
        });
    } catch (error) {
        console.error('Error saat hashing password:', error);
        res.status(500).send('Terjadi kesalahan server.');
    }
});

app.post('/admin/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send('Email dan password wajib diisi!');

    const query = 'SELECT * FROM admin WHERE email = ?';
    db.query(query, [email], async (err, admins) => {
        if (err || admins.length === 0) return res.status(401).send('Email atau Password salah.');

        const admin = admins[0];
        const match = await bcrypt.compare(password, admin.password);

        if (match) {
            req.session.isAdmin = true;
            req.session.adminId = admin.id;
            req.session.adminEmail = admin.email;
            res.redirect('/admin/dashboard');
        } else {
            res.status(401).send('Email atau Password salah.');
        }
    });
});

app.get('/admin/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.redirect('/admin/dashboard');
        res.redirect('/');
    });
});

// --- Admin Dashboard & Read (R) ---

app.get('/admin/dashboard', isAuthenticated, (req, res) => {
    const usersQuery = 'SELECT id, first_name, last_name, email, created_at FROM user ORDER BY id DESC';
    const apiKeysQuery = 'SELECT ma.id, ma.api_name, ma.api_key, ma.expiry_date, u.email as user_email, u.first_name, u.last_name, ma.created_at FROM masuk_api ma JOIN user u ON ma.user_id = u.id ORDER BY ma.id DESC';

    db.query(usersQuery, (err, users) => {
        if (err) return res.status(500).send('Gagal mengambil data user.');

        db.query(apiKeysQuery, (err, apiKeys) => {
            if (err) return res.status(500).send('Gagal mengambil data API Key.');

            res.send(getAdminDashboardHtml(req.session.adminEmail, users, apiKeys));
        });
    });
});

// --- CRUD: User Update (U) ---

app.get('/admin/users/edit/:id', isAuthenticated, (req, res) => {
    const userId = req.params.id;
    const query = 'SELECT id, first_name, last_name, email FROM user WHERE id = ?';

    db.query(query, [userId], (err, users) => {
        if (err || users.length === 0) {
            return res.status(404).send('User tidak ditemukan.');
        }
        res.send(getEditUserForm(users[0]));
    });
});

app.post('/admin/users/update/:id', isAuthenticated, (req, res) => {
    const userId = req.params.id;
    const { firstName, lastName, email } = req.body;

    if (!firstName || !lastName || !email) {
        return res.status(400).send('Semua kolom user harus diisi!');
    }

    const query = 'UPDATE user SET first_name = ?, last_name = ?, email = ? WHERE id = ?';
    db.query(query, [firstName, lastName, email, userId], (err) => {
        if (err) {
            console.error('Gagal mengupdate user:', err);
            return res.status(500).send('Gagal mengupdate user ke database.');
        }
        res.send(getSuccessMessage('Data User berhasil diupdate!', '<a href="/admin/dashboard">Kembali ke Dashboard</a>'));
    });
});

// --- CRUD: User Delete (D) ---

app.post('/admin/users/delete/:id', isAuthenticated, (req, res) => {
    const userId = req.params.id;
    const query = 'DELETE FROM user WHERE id = ?';

    db.query(query, [userId], (err) => {
        if (err) {
            console.error('Gagal menghapus user:', err);
            return res.status(500).send('Gagal menghapus user dari database.');
        }
        res.send(getSuccessMessage('User dan semua API Keys terkait berhasil dihapus!', '<a href="/admin/dashboard">Kembali ke Dashboard</a>'));
    });
});

// --- CRUD: API Key Delete (D) ---

app.post('/admin/api-keys/delete/:id', isAuthenticated, (req, res) => {
    const keyId = req.params.id;
    const query = 'DELETE FROM masuk_api WHERE id = ?';

    db.query(query, [keyId], (err) => {
        if (err) {
            console.error('Gagal menghapus API Key:', err);
            return res.status(500).send('Gagal menghapus API Key dari database.');
        }
        res.send(getSuccessMessage('API Key berhasil dihapus!', '<a href="/admin/dashboard">Kembali ke Dashboard</a>'));
    });
});

// --- PROTECTED API ENDPOINTS (Dilindungi oleh apiAuthMiddleware) ---

app.get('/api/users', apiAuthMiddleware, (req, res) => {
    // API endpoint untuk mendapatkan semua data user
    const usersQuery = 'SELECT id, first_name, last_name, email, created_at FROM user ORDER BY id DESC';
    db.query(usersQuery, (err, users) => {
        if (err) {
            console.error('Gagal mengambil data user untuk API:', err);
            return res.status(500).json({ success: false, message: 'Kesalahan Server Internal.' });
        }
        res.json({ success: true, count: users.length, data: users });
    });
});

app.get('/api/api-keys', apiAuthMiddleware, (req, res) => {
    // API endpoint untuk mendapatkan semua data API Key
    const apiKeysQuery = 'SELECT ma.id, ma.api_name, ma.api_key, ma.expiry_date, u.email as user_email, ma.created_at FROM masuk_api ma JOIN user u ON ma.user_id = u.id ORDER BY ma.id DESC';
    db.query(apiKeysQuery, (err, apiKeys) => {
        if (err) {
            console.error('Gagal mengambil data API Key untuk API:', err);
            return res.status(500).json({ success: false, message: 'Kesalahan Server Internal.' });
        }

        // Hitung status untuk setiap kunci sebelum dikirim
        const dataWithStatus = apiKeys.map(key => ({
            id: key.id,
            api_name: key.api_name,
            api_key: key.api_key,
            user_email: key.user_email,
            created_at: key.created_at,
            expiry_date: key.expiry_date,
            status: checkKeyStatus(key.expiry_date)
        }));

        res.json({ success: true, count: dataWithStatus.length, data: dataWithStatus });
    });
});

// --- HTML Helper Functions (untuk Admin UI yang diperbarui) ---

function getBaseHtml(title, bodyContent) {
    return `
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <title>${title}</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                :root {
                    --primary: #6c63ff;
                    --primary-dark: #5a52d5;
                    --secondary: #ff6584;
                    --accent: #36d1dc;
                    --dark: #2c3e50;
                    --light: #f8f9fa;
                    --success: #2ecc71;
                    --warning: #f39c12;
                    --danger: #e74c3c;
                    --gray: #95a5a6;
                    --card-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                    --transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
                }

                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    background: linear-gradient(135deg, #89c4f4, #c9daf8, #2e3de0);
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    min-height: 100vh; 
                    padding: 20px;
                    position: relative;
                    overflow-x: hidden;
                }
                
                body::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000"><polygon fill="rgba(255,255,255,0.05)" points="0,1000 1000,0 1000,1000"/></svg>');
                    z-index: -1;
                }
                
                .card { 
                    background: rgba(255, 255, 255, 0.95); 
                    padding: 40px; 
                    border-radius: 24px; 
                    box-shadow: var(--card-shadow); 
                    width: 100%; 
                    max-width: 450px; 
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    position: relative;
                    transition: var(--transition);
                }
                
                .card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
                }
                
                .card::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 5px;
                    background: linear-gradient(90deg, var(--primary), var(--secondary), var(--accent));
                    border-radius: 24px 24px 0 0;
                }
                
                h2 { 
                    text-align: center; 
                    color: var(--dark); 
                    margin-bottom: 25px; 
                    font-size: 1.8rem; 
                    font-weight: 700;
                }
                
                .form-group { 
                    margin-bottom: 20px; 
                }
                
                label { 
                    display: block; 
                    margin-bottom: 8px; 
                    font-weight: 600; 
                    color: var(--dark); 
                }
                
                input[type="email"], input[type="password"], input[type="text"] { 
                    width: 100%; 
                    padding: 16px 20px; 
                    border: 2px solid #e0e0e0; 
                    border-radius: 12px; 
                    box-sizing: border-box; 
                    font-size: 1rem;
                    transition: var(--transition);
                    background-color: #f9f9f9;
                }
                
                input[type="email"]:focus, input[type="password"]:focus, input[type="text"]:focus {
                    border-color: var(--primary);
                    background-color: white;
                    box-shadow: 0 0 0 4px rgba(108, 99, 255, 0.1);
                    outline: none;
                }
                
                button { 
                    background: linear-gradient(135deg, var(--primary), var(--primary-dark)); 
                    color: white; 
                    border: none; 
                    padding: 16px; 
                    border-radius: 12px; 
                    cursor: pointer; 
                    width: 100%; 
                    margin-top: 15px; 
                    font-weight: 600;
                    font-size: 1rem;
                    transition: var(--transition);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    gap: 10px;
                }
                
                button:hover { 
                    background: linear-gradient(135deg, var(--primary-dark), var(--primary));
                    transform: translateY(-2px);
                    box-shadow: 0 10px 20px rgba(108, 99, 255, 0.3);
                }
                
                .link-container { 
                    text-align: center; 
                    margin-top: 25px; 
                    font-size: 0.9em; 
                }
                
                .link-container a { 
                    color: var(--primary); 
                    text-decoration: none; 
                    font-weight: 600;
                    transition: var(--transition);
                }
                
                .link-container a:hover { 
                    color: var(--primary-dark);
                    text-decoration: underline; 
                }
                
                .success-box { 
                    background: linear-gradient(135deg, #f0fff0, #e0ffe0);
                    border: 2px solid var(--success); 
                    color: #006600; 
                    padding: 20px; 
                    border-radius: 12px; 
                    text-align: center; 
                    margin-bottom: 20px; 
                }
                
                .success-box h3 { 
                    margin-bottom: 10px; 
                    color: var(--success);
                }
                
                .danger-btn { 
                    background: var(--danger); 
                }
                
                .danger-btn:hover { 
                    background: #c0392b; 
                }
            </style>
        </head>
        <body>
            <div class="card">
                ${bodyContent}
            </div>
        </body>
        </html>
    `;
}

function getSuccessMessage(title, linkHtml) {
    const content = `
        <div class="success-box">
            <h3><i class="fas fa-check-circle"></i> ${title}</h3>
            <p>${linkHtml}</p>
        </div>
    `;
    return getBaseHtml('Sukses', content);
}

function getAdminLoginForm() {
    const content = `
        <h2><i class="fas fa-user-shield"></i> Admin Login</h2>
        <form method="POST" action="/admin/login">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" placeholder="Email admin Anda" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Password Anda" required>
            </div>
            <button type="submit"><i class="fas fa-sign-in-alt"></i> Login</button>
        </form>
        <div class="link-container">
            Belum punya akun? <a href="/admin/register">Register Admin</a>
        </div>
        <div class="link-container">
            <a href="/"><i class="fas fa-arrow-left"></i> Kembali ke Halaman Utama</a>
        </div>
    `;
    return getBaseHtml('Admin Login', content);
}

function getAdminRegisterForm() {
    const content = `
        <h2><i class="fas fa-user-plus"></i> Admin Register</h2>
        <form method="POST" action="/admin/register">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" placeholder="Email admin Anda" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Buat password yang kuat" required>
            </div>
            <button type="submit"><i class="fas fa-user-plus"></i> Register</button>
        </form>
        <div class="link-container">
            Sudah punya akun? <a href="/admin/login">Login Admin</a>
        </div>
        <div class="link-container">
            <a href="/"><i class="fas fa-arrow-left"></i> Kembali ke Halaman Utama</a>
        </div>
    `;
    return getBaseHtml('Admin Register', content);
}

function getEditUserForm(user) {
    const content = `
        <h2><i class="fas fa-user-edit"></i> Edit User: ${user.first_name}</h2>
        <form method="POST" action="/admin/users/update/${user.id}">
            <div class="form-group">
                <label for="firstName">Nama Depan</label>
                <input type="text" id="firstName" name="firstName" value="${user.first_name}" required>
            </div>
            <div class="form-group">
                <label for="lastName">Nama Belakang</label>
                <input type="text" id="lastName" name="lastName" value="${user.last_name}" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" value="${user.email}" required>
            </div>
            <button type="submit"><i class="fas fa-save"></i> Simpan Perubahan</button>
        </form>
        <div class="link-container">
            <a href="/admin/dashboard"><i class="fas fa-arrow-left"></i> Batal dan Kembali</a>
        </div>
    `;
    return getBaseHtml('Edit User', content);
}

function getAdminDashboardHtml(adminEmail, users, apiKeys) {
    const userRows = users.map(u => `
        <tr>
            <td>${u.id}</td>
            <td>${u.first_name} ${u.last_name}</td>
            <td>${u.email}</td>
            <td>${u.created_at ? new Date(u.created_at).toLocaleString('id-ID') : 'N/A'}</td>
            <td class="action-cell">
                <a href="/admin/users/edit/${u.id}" class="action-btn edit-btn"><i class="fas fa-edit"></i> Edit</a>
                <form method="POST" action="/admin/users/delete/${u.id}" onsubmit="return confirm('Apakah Anda yakin ingin menghapus user ID ${u.id}? Ini akan menghapus semua API Keys yang terkait!');">
                    <button type="submit" class="action-btn delete-btn"><i class="fas fa-trash"></i> Hapus</button>
                </form>
            </td>
        </tr>
    `).join('');

    const apiKeyRows = apiKeys.map(k => {
        const status = checkKeyStatus(k.expiry_date);
        const statusClass = status === 'ON' ? 'status-on' : 'status-off';
        const expiryDate = k.expiry_date ? new Date(k.expiry_date).toLocaleDateString('id-ID') : 'N/A';
        
        return `
            <tr>
                <td>${k.id}</td>
                <td>${k.api_name}</td>
                <td><span class="api-key-value">${k.api_key.substring(0, 10)}...</span></td>
                <td><span class="${statusClass}">${status}</span></td>
                <td>${expiryDate}</td>
                <td>${k.first_name} (${k.user_email})</td>
                <td>${k.created_at ? new Date(k.created_at).toLocaleString('id-ID') : 'N/A'}</td>
                <td class="action-cell">
                    <form method="POST" action="/admin/api-keys/delete/${k.id}" onsubmit="return confirm('Apakah Anda yakin ingin menghapus API Key ID ${k.id} (${k.api_name})?');">
                        <button type="submit" class="action-btn delete-btn"><i class="fas fa-trash"></i> Hapus</button>
                    </form>
                </td>
            </tr>
        `;
    }).join('');

    return `
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <title>Admin Dashboard</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                :root {
                    --primary: #6c63ff;
                    --primary-dark: #5a52d5;
                    --secondary: #ff6584;
                    --accent: #36d1dc;
                    --dark: #2c3e50;
                    --light: #f8f9fa;
                    --success: #2ecc71;
                    --warning: #f39c12;
                    --danger: #e74c3c;
                    --gray: #95a5a6;
                    --card-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                    --transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
                }

                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    background: linear-gradient(135deg, #89c4f4, #c9daf8, #2e3de0);
                    padding: 20px; 
                    min-height: 100vh;
                    position: relative;
                }
                
                body::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000"><polygon fill="rgba(255,255,255,0.05)" points="0,1000 1000,0 1000,1000"/></svg>');
                    z-index: -1;
                }
                
                .header { 
                    display: flex; 
                    justify-content: space-between; 
                    align-items: center; 
                    margin-bottom: 30px; 
                    background: rgba(255, 255, 255, 0.95); 
                    padding: 25px; 
                    border-radius: 16px; 
                    box-shadow: var(--card-shadow);
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                }
                
                h1 { 
                    color: var(--dark); 
                    font-size: 2rem;
                    font-weight: 700;
                }
                
                .logout-btn { 
                    background: var(--danger); 
                    color: white; 
                    border: none; 
                    padding: 12px 20px; 
                    border-radius: 10px; 
                    cursor: pointer; 
                    text-decoration: none; 
                    font-weight: 600;
                    transition: var(--transition);
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                
                .logout-btn:hover { 
                    background: #ff1900ff; 
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(231, 76, 60, 0.3);
                }
                
                h2 { 
                    color: var(--primary); 
                    border-bottom: 3px solid var(--primary); 
                    padding-bottom: 10px; 
                    margin-top: 40px; 
                    margin-bottom: 20px; 
                    font-size: 1.5rem; 
                    font-weight: 600;
                }
                
                .table-container { 
                    background: rgba(255, 255, 255, 0.95); 
                    padding: 25px; 
                    border-radius: 16px; 
                    box-shadow: var(--card-shadow); 
                    overflow-x: auto; 
                    margin-bottom: 30px; 
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                }
                
                table { 
                    width: 100%; 
                    border-collapse: collapse; 
                }
                
                th, td { 
                    border: 1px solid #e0e0e0; 
                    padding: 15px; 
                    text-align: left; 
                }
                
                th { 
                    background: linear-gradient(135deg, var(--primary), var(--primary-dark));
                    color: white; 
                    font-weight: 600;
                }
                
                tr:nth-child(even) { 
                    background-color: rgba(108, 99, 255, 0.03); 
                }
                
                tr:hover {
                    background-color: rgba(108, 99, 255, 0.08);
                    transition: var(--transition);
                }
                
                code, .api-key-value { 
                    background: #eee; 
                    padding: 4px 8px; 
                    border-radius: 6px; 
                    font-size: 0.9em; 
                    font-family: 'Courier New', monospace;
                }
                
                .action-cell {
                    display: flex;
                    gap: 8px;
                    border: none;
                    align-items: center;
                }
                
                .action-btn { 
                    padding: 8px 12px; 
                    border: none; 
                    border-radius: 8px; 
                    cursor: pointer; 
                    font-size: 0.9em; 
                    text-decoration: none; 
                    transition: var(--transition); 
                    color: white;
                    display: flex;
                    align-items: center;
                    gap: 5px;
                    font-weight: 600;
                }
                
                .edit-btn { 
                    background: var(--warning); 
                }
                
                .edit-btn:hover { 
                    background: #e67e22; 
                    transform: translateY(-2px);
                }
                
                .delete-btn { 
                    background: var(--danger); 
                }
                
                .delete-btn:hover { 
                    background: #c0392b; 
                    transform: translateY(-2px);
                }
                
                .status-on { 
                    background-color: var(--success); 
                    color: white; 
                    padding: 6px 12px; 
                    border-radius: 20px; 
                    font-weight: bold; 
                    font-size: 0.85em;
                }
                
                .status-off { 
                    background-color: var(--warning); 
                    color: white; 
                    padding: 6px 12px; 
                    border-radius: 20px; 
                    font-weight: bold; 
                    font-size: 0.85em;
                }
                
                .api-info-box {
                    background: linear-gradient(135deg, #f0f7ff, #e1f0ff);
                    border: 2px solid var(--primary);
                    border-radius: 16px;
                    padding: 25px;
                    margin-bottom: 30px;
                    position: relative;
                    overflow: hidden;
                }
                
                .api-info-box::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100"><rect fill="none" stroke="rgba(108, 99, 255, 0.1)" stroke-width="2" x="10" y="10" width="80" height="80" rx="10"/></svg>');
                    z-index: 0;
                }
                
                .api-info-box h3 {
                    color: var(--primary);
                    margin-bottom: 15px;
                    font-size: 1.3rem;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    position: relative;
                    z-index: 1;
                }
                
                .api-info-box ul {
                    padding-left: 20px;
                    position: relative;
                    z-index: 1;
                }
                
                .api-info-box li {
                    margin-bottom: 8px;
                    position: relative;
                }
                
                .api-info-box li::before {
                    content: '•';
                    color: var(--primary);
                    font-weight: bold;
                    display: inline-block;
                    width: 1em;
                    margin-left: -1em;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1><i class="fas fa-tachometer-alt"></i> Admin Dashboard</h1>
                <div style="display: flex; align-items: center; gap: 15px;">
                    <span>Selamat datang, <strong>${adminEmail}</strong>!</span>
                    <a href="/admin/logout" class="logout-btn"><i class="fas fa-sign-out-alt"></i> Logout</a>
                </div>
            </div>
            
            <div class="api-info-box">
                <h3><i class="fas fa-shield-alt"></i> Informasi Endpoint API</h3>
                <p>Endpoint berikut dilindungi oleh <strong>API Key</strong>. Akses menggunakan kunci yang valid di header <code>X-API-Key</code> atau sebagai parameter <code>api_key</code>.</p>
                <ul>
                    <li>GET: <code>/api/users</code> - Mendapatkan semua data user</li>
                    <li>GET: <code>/api/api-keys</code> - Mendapatkan semua data API Key</li>
                </ul>
            </div>

            <h2><i class="fas fa-users"></i> Daftar Users (${users.length})</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Nama Lengkap</th>
                            <th>Email</th>
                            <th>Terdaftar Sejak</th>
                            <th>Aksi</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${userRows || '<tr><td colspan="5" style="text-align: center; padding: 20px;">Tidak ada data user.</td></tr>'}
                    </tbody>
                </table>
            </div>

            <h2><i class="fas fa-key"></i> Daftar API Keys (${apiKeys.length})</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>ID Key</th>
                            <th>Nama Key</th>
                            <th>Key (Partial)</th>
                            <th>Status</th>
                            <th>Kadaluarsa</th>
                            <th>User</th>
                            <th>Tanggal Dibuat</th>
                            <th>Aksi</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${apiKeyRows || '<tr><td colspan="8" style="text-align: center; padding: 20px;">Tidak ada data API Key.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </body>
        </html>
    `;
}

// Jalankan server
app.listen(port, () => {
    console.log(`Server berjalan di http://localhost:${port}`);
});

// Tes koneksi database
db.query('SELECT 1 + 1 AS result', (err, results) => {
    if (err) console.error('Tes koneksi gagal:', err);
    else console.log('Tes koneksi sukses:', results);
});