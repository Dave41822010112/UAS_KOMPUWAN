from werkzeug.security import generate_password_hash

# Gantikan 'password_saya' dengan password yang ingin Anda hash
password_hash = generate_password_hash('suster123', method='pbkdf2:sha256')
print(password_hash)