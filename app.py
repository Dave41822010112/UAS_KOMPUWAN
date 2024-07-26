import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for
from pymongo import MongoClient
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Memuat variabel lingkungan dari file .env
load_dotenv()

# Inisialisasi aplikasi Flask
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'supersecretkey')

# Memuat kunci enkripsi dari variabel lingkungan
key = os.getenv('ENCRYPTION_KEY')
if key is None:
    raise ValueError("ENCRYPTION_KEY environment variable not set")
cipher_suite = Fernet(key.encode())

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Setup koneksi ke MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client.medical_records
records_collection = db.records
users_collection = db.users

# Konfigurasi logging
logging.basicConfig(level=logging.INFO)

# Handler untuk log aplikasi umum
app_handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
app_handler.setLevel(logging.INFO)
app_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
app_handler.setFormatter(app_formatter)

# Handler untuk log audit
audit_handler = RotatingFileHandler('audit.log', maxBytes=10000, backupCount=1)
audit_handler.setLevel(logging.INFO)
audit_formatter = logging.Formatter('%(asctime)s - %(message)s')
audit_handler.setFormatter(audit_formatter)

# Logger untuk aplikasi
app_logger = logging.getLogger('app')
app_logger.addHandler(app_handler)

# Logger untuk audit
audit_logger = logging.getLogger('audit')
audit_logger.addHandler(audit_handler)

class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user:
        return User(user_id, user.get('role', ''))
    return None

def role_required(roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            app_logger.info(f'User {current_user.id} with role {current_user.role} attempting to access {func.__name__}')
            if current_user.role not in roles:
                app_logger.warning(f'Access denied for user {current_user.id} with role {current_user.role} to {func.__name__}')
                return "Access denied", 403
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/')
@login_required
def index():
    records = records_collection.find()
    decrypted_records = []

    for record in records:
        try:
            decrypted_diagnosis = cipher_suite.decrypt(record['diagnosis'].encode()).decode()
            decrypted_records.append({
                'name': record['name'],
                'age': record['age'],
                'diagnosis': decrypted_diagnosis,
                '_id': str(record['_id'])
            })
        except Exception as e:
            app_logger.error(f"Decryption Error: {e} for record {record}")

    return render_template('index.html', records=decrypted_records)

@app.route('/add', methods=['POST'])
@login_required
@role_required(['Dokter'])
def add_record():
    name = request.form.get('name')
    age = request.form.get('age')
    diagnosis = request.form.get('diagnosis')

    try:
        encrypted_diagnosis = cipher_suite.encrypt(diagnosis.encode()).decode()
        records_collection.insert_one({
            'name': name,
            'age': age,
            'diagnosis': encrypted_diagnosis
        })
        app_logger.info(f'Record added by {current_user.id}: {name}, {age}')
    except Exception as e:
        app_logger.error(f"Database Insert Error: {e}")

    return redirect(url_for('index'))

@app.route('/delete/<record_id>', methods=['POST'])
@login_required
@role_required(['Dokter'])
def delete_record(record_id):
    try:
        records_collection.delete_one({'_id': ObjectId(record_id)})
        app_logger.info(f'Record deleted by {current_user.id}: {record_id}')
    except Exception as e:
        app_logger.error(f"Database Delete Error: {e}")

    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        app_logger.info(f'Login attempt: {username}, Role: {role}')

        user = users_collection.find_one({"username": username})

        if user:
            app_logger.info(f'User found in database: {user["username"]}')
        else:
            app_logger.warning(f'User not found: {username}')
            return "Invalid credentials or role", 403

        if user and check_password_hash(user['password'], password) and user['role'] == role:
            user_id = str(user['_id'])
            login_user(User(user_id, user['role']))
            app_logger.info(f'User logged in: {username} with role {role}')
            return redirect(url_for('index'))
        else:
            app_logger.warning(f'Failed login attempt: {username} with role {role}')
            return "Invalid credentials or role", 403
    return render_template('login.html')

@app.route('/logout')   
@login_required
def logout():
    app_logger.info(f'User logged out: {current_user.id}')
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        if role not in ['Dokter', 'Suster']:
            return "Invalid role", 400

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'role': role
        })
        app_logger.info(f'User registered: {username} with role {role}')
        return redirect(url_for('login'))
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)
