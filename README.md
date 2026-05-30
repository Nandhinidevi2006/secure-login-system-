# 🔐 Secure Login System

A comprehensive, production-ready secure login web application built with Flask featuring user authentication, password hashing, Two-Factor Authentication (2FA), and protection against common web vulnerabilities.

## ✨ Key Features

### 🔐 Security Features
- **Bcrypt Password Hashing**: Industry-standard password hashing with salt
- **SQL Injection Protection**: Input sanitization and parameterized queries
- **Rate Limiting**: Prevent brute-force attacks (10 attempts/hour for login)
- **Account Lockout**: Automatic account lock after 5 failed login attempts (15 minutes)
- **HTTPS Secure Cookies**: HttpOnly and Secure flags enabled
- **Session Management**: Secure session handling with automatic timeout
- **Two-Factor Authentication (2FA)**: TOTP (Time-based One-Time Password)
- **Backup Codes**: 10 backup codes for account recovery

### 👤 User Management
- **User Registration**: Email validation, strong password requirements
- **Login System**: Username or email login
- **Session Management**: Automatic logout after inactivity
- **Profile Management**: Change password, manage security settings
- **Account Information**: View login history and account details

### 🛡️ Validation & Protection
- **Email Validation**: RFC-compliant email format checking
- **Password Strength Requirements**:
  - Minimum 8 characters
  - Uppercase letter required
  - Lowercase letter required
  - Number required
  - Special character required
- **Username Validation**: 3-80 characters, alphanumeric with underscore/hyphen
- **Input Sanitization**: Prevent XSS and injection attacks

## 📋 Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Setup Steps

1. **Clone the repository**:
```bash
cd "c:\Users\nandh\Downloads\task 4"
```

2. **Create virtual environment** (if not already created):
```bash
python -m venv .venv
.\.venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r secure_login_requirements.txt
```

4. **Run the application**:
```bash
python secure_login.py
```

5. **Access the application**:
Open your browser and navigate to: `http://localhost:5001`

## 🚀 Usage

### User Registration
1. Click "Register" on the login page
2. Enter username (3-80 characters, alphanumeric)
3. Enter valid email address
4. Create strong password meeting all requirements
5. Confirm password
6. Click "Create Account"

### User Login
1. Enter username or email
2. Enter password
3. If 2FA is enabled, enter 6-digit code from authenticator app
4. Click "Login"

### Setting Up 2FA
1. Log in to your account
2. Go to "Profile" → "Two-Factor Authentication"
3. Click "Enable 2FA"
4. Scan QR code with authenticator app (Google Authenticator, Authy, etc.)
5. Enter 6-digit code from app
6. Save backup codes securely
7. 2FA is now enabled

### Disabling 2FA
1. Go to Profile settings
2. Click "Disable 2FA"
3. Enter your password
4. 2FA is disabled

## 🗄️ Database Schema

### Users Table
```
id (Integer, Primary Key)
username (String, Unique, Indexed)
email (String, Unique, Indexed)
password_hash (String)
created_at (DateTime)
last_login (DateTime)
is_active (Boolean)
totp_secret (String)
totp_enabled (Boolean)
backup_codes (Text)
failed_login_attempts (Integer)
locked_until (DateTime)
```

## 🔒 Security Best Practices Implemented

### Password Security
- ✅ Bcrypt hashing with automatic salt generation
- ✅ Password complexity requirements enforced
- ✅ Old password verification before change
- ✅ No password hints or recovery questions

### Session Security
- ✅ HttpOnly cookies (prevent JavaScript access)
- ✅ Secure flag (HTTPS only)
- ✅ Session timeout (24 hours)
- ✅ User-specific session data

### Attack Prevention
- ✅ **SQL Injection**: Input sanitization and parameterized queries
- ✅ **XSS (Cross-Site Scripting)**: Input validation and HTML escaping
- ✅ **Brute Force**: Rate limiting and account lockout
- ✅ **Session Hijacking**: Secure cookie flags
- ✅ **Credential Stuffing**: Account lockout mechanism
- ✅ **CSRF**: Flask session protection

### Input Validation
- ✅ Email format validation
- ✅ Username format validation
- ✅ Password strength validation
- ✅ Input length limits
- ✅ Special character sanitization

## 📁 Project Structure

```
secure_login.py                 # Flask backend application
secure_login_requirements.txt    # Python dependencies
templates/
├── register.html               # Registration page
├── login.html                  # Login page
├── dashboard.html              # User dashboard
├── profile.html                # Profile settings
└── setup_2fa.html             # 2FA setup page
```

## 🔧 Dependencies

```
Flask==3.1.3                    # Web framework
Flask-SQLAlchemy==3.1.1         # Database ORM
Flask-Bcrypt==1.0.1            # Password hashing
Flask-Limiter==3.5.0           # Rate limiting
PyOTP==2.9.0                   # 2FA implementation
QRCode==7.4.2                  # QR code generation
Pillow==12.2.0                 # Image processing
```

## 🔍 API Endpoints

### Authentication
- `POST /register` - User registration
- `POST /login` - User login
- `POST /verify-2fa` - Verify 2FA code
- `GET /logout` - Logout user

### User Management
- `GET /dashboard` - User dashboard
- `GET /profile` - Profile settings
- `POST /change-password` - Change password
- `POST /setup-2fa` - Setup 2FA
- `POST /disable-2fa` - Disable 2FA

## 🧪 Testing

### Test Credentials
```
Username: testuser
Email: test@example.com
Password: TestPassword@123
```

### Common Test Cases
1. Register new user with valid data
2. Register with duplicate email
3. Login with wrong password
4. Login after account lockout
5. Enable/disable 2FA
6. Change password
7. Access dashboard without login (should redirect)

## 🚨 Common Errors & Solutions

| Error | Solution |
|-------|----------|
| `ModuleNotFoundError` | Run `pip install -r secure_login_requirements.txt` |
| `Address already in use` | Port 5001 is in use. Change port in `secure_login.py` |
| `Database locked` | Close all connections and restart the app |
| `2FA code invalid` | Ensure correct time synchronization on device |

## 🔐 Password Requirements

Users must create passwords with:
- ✅ At least 8 characters
- ✅ Uppercase letter (A-Z)
- ✅ Lowercase letter (a-z)
- ✅ Number (0-9)
- ✅ Special character (!@#$%^&*)

Example strong password: `SecurePass@123`

## 📱 2FA Setup Guide

### Supported Authenticator Apps
- Google Authenticator
- Microsoft Authenticator
- Authy
- FreeOTP
- Any TOTP-compatible app

### Backup Codes
- 10 codes generated during 2FA setup
- Each code can be used only once
- Use if you lose access to authenticator
- Store safely offline

## 🌐 Deployment Considerations

For production deployment:
1. Use environment variables for secrets
2. Enable HTTPS/SSL
3. Use production WSGI server (Gunicorn, uWSGI)
4. Set `debug=False`
5. Use persistent database (PostgreSQL recommended)
6. Implement logging and monitoring
7. Set up regular database backups
8. Configure CORS if needed

## 📝 Configuration

Edit `secure_login.py` to configure:
```python
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_login.db'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
```

## 🔄 Account Lockout Policy

- Failed login attempts tracked per user
- Account locked after 5 failed attempts
- Lockout duration: 15 minutes
- Counter resets on successful login
- Users can use backup codes during lockout (if 2FA enabled)

## 📊 Features Comparison

| Feature | Included |
|---------|----------|
| User Registration | ✅ |
| Secure Login | ✅ |
| Password Hashing (Bcrypt) | ✅ |
| 2FA (TOTP) | ✅ |
| Backup Codes | ✅ |
| Rate Limiting | ✅ |
| Account Lockout | ✅ |
| Session Management | ✅ |
| SQL Injection Protection | ✅ |
| Input Validation | ✅ |
| Password Change | ✅ |
| Logout | ✅ |

## 🤝 Contributing

Feel free to fork and submit pull requests for improvements.

## 📄 License

This project is provided as-is for educational and development purposes.

## 🔗 Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Bcrypt Best Practices](https://auth0.com/blog/hashing-passwords-one-way-road-to-security/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PyOTP Documentation](https://pyauth.github.io/pyotp/)

## 📞 Support

For issues or questions, please review the code comments and consult the documentation above.

---

**Last Updated**: May 24, 2026  
**Version**: 1.0.0  
**Status**: Production Ready
