from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
import hashlib
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database';
db = SQLAlchemy(app)
app.secret_key = 'secret key'


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100))

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        salt = os.urandom(16) 
        self.password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000).hex() + salt.hex() 

    def check_password(self, password):
        stored_password, salt = self.password[:64], bytes.fromhex(self.password[64:])
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000).hex()
        return hashed_password == stored_password  
    
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return 'API is working'

@app.route('/signup', methods=['POST'])
def register():
    name = request.json['name']
    email = request.json['email']
    password = request.json['password']

    new_user = User(name=name, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'})

@app.route('/login', methods=['POST'])
def login():
    email = request.json['email']
    password = request.json['password']

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'error': 'Invalid user'}), 401

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        return jsonify({'user': user.name})
    else:
        return jsonify({'error': 'Unauthorized'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('email', None)
    return jsonify({'message': 'Logged out successfully'})

if __name__ == '__main__':
    app.run(debug=True)