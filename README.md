# 🛡️ SteganoSafe — Secure File Sharing System

A **production-style secure file sharing platform** that combines **AES-256-GCM encryption** with **steganographic image embedding** to securely hide and share files inside PNG images.

---

## ✨ Features

### 🔐 Security
- **AES-256-GCM** encryption for all uploaded files
- **PBKDF2-SHA256** password hashing (100,000 iterations, per-user salt)
- **Session-based** authentication with 30-minute auto-expiry
- **Role-Based Access Control** (Admin / User)
- **Rate limiting** on login endpoints (5 attempts/minute)
- **Security headers** on all responses (CSP, HSTS, X-Frame-Options, etc.)
- **Complete audit logging** of all actions

### 📁 File Management
- Upload files (up to **50 MB**) with password-protected encryption
- Files are hidden inside **PNG cover images** (100 KB – 10 MB) using steganography
- Download and decrypt files with the original encryption password
- **Decrypt Tool** for standalone file decryption
- SHA-256 hash verification for data integrity

### 🖼️ Hybrid Steganography
- **Multi-bit LSB** embedding for small payloads (≤ 2 bits/channel, nearly invisible)
- **IEND-append** technique for large payloads (zero image quality loss)
- **Auto-selection** between strategies based on payload size
- **zlib compression** (level 9) to minimize embedded data size
- **CRC32** tamper detection on extraction

### 👥 User Management (Admin)
- Create, edit, and delete users
- Role assignment (Admin / User)
- User activity monitoring
- Session management

### 📊 Dashboard & Monitoring
- **Admin Dashboard**: System overview, **interactive donut pie chart** for security events, recent activity timeline
- **User Dashboard**: Personal file stats, security breakdown panel
- **Real-time notifications**: Bell icon with dropdown showing recent security events
- **Clickable stat cards**: Navigate directly to File Vault, User Management, Audit Logs, or Security from dashboard cards

### 🎨 UI Features
- **Collapsible sidebar**: Toggle between full and icon-only sidebar (state persists across pages)
- **Role-aware navigation**: Dashboard link auto-adjusts for Admin vs User roles on shared pages
- **Dark mode neumorphic design**: Glassmorphism effects, smooth animations, and gradient accents
- **Session timer**: Live countdown in the header with auto-logout on expiry
- **Responsive layout**: Works across different screen sizes

---

## 📋 Prerequisites

- **Python 3.10** or higher
- **pip** (Python package manager)

---

## 🚀 Getting Started

### 1. Clone or download the project

```bash
cd "c:\Users\91834\3D Objects\stegno"
```

### 2. (Recommended) Create a virtual environment

**Windows:**
```powershell
python -m venv venv
.\venv\Scripts\Activate
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the server

```bash
python server.py
```

You should see:
```
============================================================
  SteganoSafe — Secure File Sharing System
============================================================
  Server:    http://127.0.0.1:8000
  Data Dir:  .../data
  Database:  .../data/steganosafe.db
============================================================
  [*] Server starting (multi-threaded)...
  [*] Open http://127.0.0.1:8000 in your browser
============================================================
```

### 5. Open in your browser

```
http://127.0.0.1:8000
```

---

## 👤 Default Admin Login

A default **admin** account is pre-configured:

| Field | Value |
|---|---|
| **Username** | `admin` |
| **Password** | `admin123` |

1. Open `http://127.0.0.1:8000/login`
2. Log in with the credentials above
3. You'll be redirected to the **Admin Dashboard**

> ⚠️ **Security:** Change the default admin password immediately after first login via **Security Settings**.

### Registering New Users

- Navigate to `http://127.0.0.1:8000/register` to create a new user account
- Username must be ≥ 3 characters, password ≥ 8 characters
- New users are assigned the `user` role by default
- Admins can manage users and roles from the **User Management** page

---

## 📖 How to Use

### Uploading a File (Encrypt & Embed)

1. Go to **File Vault** from the sidebar
2. Click **Upload Secure File**
3. Select the **file** you want to hide (up to 50 MB)
4. Select a **cover image** (PNG, 100 KB – 10 MB)
5. Enter an **encryption password** (you'll need this to decrypt later)
6. Click **Encrypt & Embed**

The system will:
- Encrypt your file with AES-256-GCM
- Compress the encrypted payload with zlib
- Embed it into the cover image using steganography
- Store the resulting stego image

### Downloading a File (Extract & Decrypt)

1. Go to **File Vault**
2. Find your file in the table
3. Click the **Download** button
4. Enter your **encryption password**
5. The original file will be extracted, decrypted, and downloaded

### Using the Decrypt Tool

1. Go to **Decrypt Tool** from the sidebar
2. Upload a **stego image** (PNG file that contains hidden data)
3. Enter the **encryption password**
4. The hidden file will be extracted and downloaded

---

## 📂 Project Structure

```
stegno/
├── server.py                 # Main HTTP server (port 8000)
├── requirements.txt          # Python dependencies
├── README.md                 # This file
│
├── modules/                  # Backend modules
│   ├── __init__.py
│   ├── auth.py               # Authentication & session management
│   ├── audit.py              # Audit logging
│   ├── crypto_utils.py       # AES-256-GCM encryption/decryption
│   ├── database.py           # SQLite database operations
│   └── steganography.py      # Hybrid steganography engine
│
├── pages/                    # HTML pages
│   ├── login.html            # Login page
│   ├── register.html         # Registration page
│   ├── dashboard.html        # User dashboard
│   ├── admin_dashboard.html  # Admin dashboard
│   ├── vault.html            # File vault (upload/download)
│   ├── decrypt.html          # Standalone decrypt tool
│   ├── security.html         # Security settings
│   ├── admin_users.html      # User management (admin only)
│   ├── admin_logs.html       # Audit logs (admin only)
│   └── admin_security.html   # Admin security overview
│
├── static/                   # Static assets
│   ├── css/style.css         # Global stylesheet
│   └── js/app.js             # Shared JavaScript utilities
│
├── data/                     # Auto-created at startup
│   ├── steganosafe.db        # SQLite database
│   ├── files/                # Temporary file storage
│   └── stego_images/         # Generated stego images
│
└── carriers/                 # Cover images folder
```

---

## 🔧 Technical Details

### Encryption Pipeline
```
File → AES-256-GCM Encrypt → SHA-256 Hash → Package Payload → zlib Compress → Embed in PNG
```

### Decryption Pipeline
```
Stego PNG → Extract Payload → zlib Decompress → Unpackage → AES-256-GCM Decrypt → Original File
```

### Steganography Strategies

| Strategy | Version | When Used | Image Quality |
|---|---|---|---|
| Multi-bit LSB | v2 | Small payloads (fits in ≤2 bits/channel) | Near-perfect |
| IEND-append | v3 | Large payloads | **Perfect** (zero modification) |

### API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/login` | User login |
| `POST` | `/api/auth/register` | User registration |
| `POST` | `/api/auth/logout` | User logout |
| `GET` | `/api/auth/check` | Check auth status |
| `GET` | `/api/files` | List user's files |
| `POST` | `/api/files/upload` | Upload & encrypt file |
| `GET` | `/api/files/download/<id>` | Download & decrypt file |
| `DELETE` | `/api/files/<id>` | Delete a file |
| `POST` | `/api/decrypt` | Decrypt a stego image |
| `GET` | `/api/stats` | System statistics |
| `GET` | `/api/activity` | Recent activity |
| `GET` | `/api/admin/logs` | Audit logs (admin) |
| `GET` | `/api/admin/users` | List users (admin) |
| `POST` | `/api/admin/users` | Create user (admin) |
| `PUT` | `/api/admin/users/<id>` | Update user (admin) |
| `DELETE` | `/api/admin/users/<id>` | Delete user (admin) |

---

## ⚠️ Important Notes

- **Cover images must be PNG format** (100 KB – 10 MB)
- **Files can be up to 50 MB**
- **Remember your encryption password** — there is no password recovery
- The session expires after **30 minutes** of inactivity
- Login is rate-limited to **5 attempts per minute** per IP
- All data is stored locally in SQLite — no external database needed

---

## 🛠️ Built With

- **Backend:** Python 3 (stdlib `http.server`, no frameworks)
- **Database:** SQLite3
- **Encryption:** `cryptography` library (AES-256-GCM, PBKDF2)
- **Steganography:** Custom hybrid engine (Multi-bit LSB + IEND-append)
- **Frontend:** Vanilla HTML, CSS, JavaScript (no frameworks)

---

## 📜 License

This project is for educational and academic purposes.
