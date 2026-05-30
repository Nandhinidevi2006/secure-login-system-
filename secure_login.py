from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from datetime import datetime, timedelta
import pyotp
import qrcode
from io import BytesIO
import base64
import secrets
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_login.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # 2FA fields
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    backup_codes = db.Column(db.Text, nullable=True)
    
    # Security fields
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def enable_totp(self):
        """Enable TOTP 2FA"""
        self.totp_secret = pyotp.random_base32()
        self.backup_codes = self.generate_backup_codes()
        return self.totp_secret
    
    def generate_backup_codes(self):
        """Generate backup codes for 2FA"""
        codes = [secrets.token_hex(4).upper() for _ in range(10)]
        return ','.join(codes)
    
    def verify_totp(self, token):
        """Verify TOTP token"""
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token)
    
    def verify_backup_code(self, code):
        """Verify and consume backup code"""
        if not self.backup_codes:
            return False
        codes = self.backup_codes.split(',')
        if code in codes:
            codes.remove(code)
            self.backup_codes = ','.join(codes)
            db.session.commit()
            return True
        return False
    
    def lock_account(self):
        """Lock account after failed attempts"""
        self.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
    
    def is_locked(self):
        """Check if account is locked"""
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        if self.locked_until and datetime.utcnow() >= self.locked_until:
            self.locked_until = None
            self.failed_login_attempts = 0
            db.session.commit()
        return False
    
    def record_login(self):
        """Record successful login"""
        self.last_login = datetime.utcnow()
        self.failed_login_attempts = 0
        self.locked_until = None
        db.session.commit()

# Validation Functions
def validate_username(username):
    """Validate username format"""
    if len(username) < 3 or len(username) > 80:
        return False, "Username must be 3-80 characters"
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username can only contain letters, numbers, underscore, and hyphen"
    return True, ""

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return True, ""
    return False, "Invalid email format"

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain special character"
    return True, ""

def sanitize_input(text):
    """Prevent SQL injection by sanitizing input"""
    if not isinstance(text, str):
        return str(text)
    # Remove or escape dangerous characters
    text = text.strip()
    # Limit length
    if len(text) > 255:
        text = text[:255]
    return text

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def register():
    if request.method == 'POST':
        data = request.get_json()
        
        username = sanitize_input(data.get('username', ''))
        email = sanitize_input(data.get('email', ''))
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        
        # Validation
        valid, msg = validate_username(username)
        if not valid:
            return jsonify({'success': False, 'message': msg}), 400
        
        valid, msg = validate_email(email)
        if not valid:
            return jsonify({'success': False, 'message': msg}), 400
        
        valid, msg = validate_password(password)
        if not valid:
            return jsonify({'success': False, 'message': msg}), 400
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registration successful! Please login.'}), 201
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def login():
    if request.method == 'POST':
        data = request.get_json()
        
        username_or_email = sanitize_input(data.get('username', ''))
        password = data.get('password', '')
        
        if not username_or_email or not password:
            return jsonify({'success': False, 'message': 'Missing username or password'}), 400
        
        # Find user
        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()
        
        if not user:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        # Check if account is locked
        if user.is_locked():
            remaining = (user.locked_until - datetime.utcnow()).total_seconds() / 60
            return jsonify({'success': False, 'message': f'Account locked. Try again in {int(remaining)} minutes'}), 403
        
        # Check password
        if not user.check_password(password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.lock_account()
                db.session.commit()
                return jsonify({'success': False, 'message': 'Account locked due to too many failed attempts'}), 403
            db.session.commit()
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        # Check if 2FA is enabled
        if user.totp_enabled:
            session['pre_2fa_user_id'] = user.id
            return jsonify({'success': True, 'message': 'Enter 2FA code', 'requires_2fa': True}), 200
        
        # Successful login
        user.record_login()
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        
        return jsonify({'success': True, 'message': 'Login successful!', 'redirect': url_for('dashboard')}), 200
    
    return render_template('login.html')

@app.route('/verify-2fa', methods=['POST'])
@limiter.limit("5 per hour")
def verify_2fa():
    if 'pre_2fa_user_id' not in session:
        return jsonify({'success': False, 'message': 'No pending 2FA verification'}), 400
    
    data = request.get_json()
    token = data.get('token', '').strip()
    use_backup = data.get('use_backup', False)
    
    user = User.query.get(session['pre_2fa_user_id'])
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if use_backup:
        if not user.verify_backup_code(token):
            return jsonify({'success': False, 'message': 'Invalid backup code'}), 401
    else:
        if not user.verify_totp(token):
            return jsonify({'success': False, 'message': 'Invalid 2FA code'}), 401
    
    # Successful 2FA verification
    user.record_login()
    session.pop('pre_2fa_user_id', None)
    session.permanent = True
    session['user_id'] = user.id
    session['username'] = user.username
    
    return jsonify({'success': True, 'message': '2FA verified!', 'redirect': url_for('dashboard')}), 200

@app.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        data = request.get_json()
        token = data.get('token', '')
        
        if not user.verify_totp(token):
            return jsonify({'success': False, 'message': 'Invalid verification code'}), 401
        
        user.totp_enabled = True
        db.session.commit()
        
        return jsonify({'success': True, 'message': '2FA enabled successfully!'}), 200
    
    # Generate QR code
    secret = user.enable_totp()
    totp = pyotp.TOTP(secret)
    
    # Create QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp.provisioning_uri(name=user.email, issuer_name='Secure Login'))
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    img_base64 = base64.b64encode(buf.getvalue()).decode()
    
    backup_codes = user.backup_codes.split(',')
    
    return render_template('setup_2fa.html', qr_code=img_base64, secret=secret, backup_codes=backup_codes)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/disable-2fa', methods=['POST'])
def disable_2fa():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    data = request.get_json()
    password = data.get('password', '')
    
    user = User.query.get(session['user_id'])
    
    if not user.check_password(password):
        return jsonify({'success': False, 'message': 'Invalid password'}), 401
    
    user.totp_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    db.session.commit()
    
    return jsonify({'success': True, 'message': '2FA disabled'}), 200

@app.route('/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    data = request.get_json()
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    
    user = User.query.get(session['user_id'])
    
    if not user.check_password(old_password):
        return jsonify({'success': False, 'message': 'Current password is incorrect'}), 401
    
    valid, msg = validate_password(new_password)
    if not valid:
        return jsonify({'success': False, 'message': msg}), 400
    
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'New passwords do not match'}), 400
    
    user.set_password(new_password)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Password changed successfully!'}), 200

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'success': False, 'message': 'Rate limit exceeded. Please try again later.'}), 429

@app.errorhandler(404)
def not_found(e):
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)
