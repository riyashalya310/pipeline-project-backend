from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
import hashlib
import os
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database';
db = SQLAlchemy(app)
app.secret_key = 'secret key'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100))
    role = db.Column(db.String(100), default='user')

    def __init__(self, email, password, name, role='user'):
        self.name = name
        self.email = email
        self.role = role
        salt = os.urandom(16) 
        self.password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000).hex() + salt.hex() 

    def check_password(self, password):
        stored_password, salt = self.password[:64], bytes.fromhex(self.password[64:])
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000).hex()
        return hashed_password == stored_password  
    
class Admin(User):
    def __init__(self, email, password, name):
        super().__init__(email, password, name, role='admin')

with app.app_context():
    db.create_all()

def create_token(user):
    payload = {
        'exp': datetime.utcnow() + timedelta(days=1),
        'iat': datetime.utcnow(),
        'sub': user.id,
        'role': user.role
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

def parse_token(token):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload['sub'], payload['role']
    except jwt.ExpiredSignatureError:
        return None, None
    except jwt.InvalidTokenError:
        return None, None

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

@app.route('/admin/signup', methods=['POST'])
def admin_register():
    name = request.json['name']
    email = request.json['email']
    password = request.json['password']

    new_admin = Admin(name=name, email=email, password=password)
    db.session.add(new_admin)
    db.session.commit()
    return jsonify({'message': 'Admin created successfully'})

@app.route('/login', methods=['POST'])
def login():
    email = request.json['email']
    password = request.json['password']

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        token = create_token(user)
        return jsonify({'token': token})
    else:
        return jsonify({'error': 'Invalid user'}), 401

@app.route('/dashboard')
def dashboard():
    token = request.headers.get('Authorization')
    if token:
        user_id, role = parse_token(token)
        if user_id and role:
            user = User.query.get(user_id)
            if user:
                return jsonify({'user': user.name})
            else:
                return jsonify({'error': 'User not found'}), 404
        else:
            return jsonify({'error': 'Invalid token'}), 401
    else:
        return jsonify({'error': 'No token provided'}), 401

@app.route('/admin/dashboard')
def admin_dashboard():
    token = request.headers.get('Authorization')
    if token:
        user_id, role = parse_token(token)
        if user_id and role == 'admin':
            user = User.query.get(user_id)
            if user:
                return jsonify({'admin': user.name})
            else:
                return jsonify({'error': 'User not found'}), 404
        else:
            return jsonify({'error': 'Invalid token or not admin'}), 401
    else:
        return jsonify({'error': 'No token provided'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    return jsonify({'message': 'Logged out successfully'})

@app.route('/admin/users', methods=['GET'])
def get_users():
    token = request.headers.get('Authorization')
    if token:
        user_id, role = parse_token(token)
        if user_id and role == 'admin':
            users = User.query.all()
            return jsonify([{'id': u.id, 'name': u.name, 'email': u.email} for u in users])
        else:
            return jsonify({'error': 'Invalid token or not admin'}), 401
    else:
        return jsonify({'error': 'No token provided'}), 401

@app.route('/admin/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    token = request.headers.get('Authorization')
    if token:
        user_id_token, role = parse_token(token)
        if user_id_token and role == 'admin':
            u = User.query.get(user_id)
            if u:
                return jsonify({'id': u.id, 'name': u.name, 'email': u.email})
            else:
                return jsonify({'error': 'User not found'}), 404
        else:
            return jsonify({'error': 'Invalid token or not admin'}), 401
    else:
        return jsonify({'error': 'No token provided'}), 401

@app.route('/admin/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    token = request.headers.get('Authorization')
    if token:
        user_id_token, role = parse_token(token)
        if user_id_token and role == 'admin':
            u = User.query.get(user_id)
            if u:
                data = request.json
                u.name = data.get('name', u.name)
                u.email = data.get('email', u.email)
                db.session.commit()
                return jsonify({'message': 'User updated successfully'})
            else:
                return jsonify({'error': 'User not found'}), 404
        else:
            return jsonify({'error': 'Invalid token or not admin'}), 401
    else:
        return jsonify({'error': 'No token provided'}), 401

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    token = request.headers.get('Authorization')
    if token:
        user_id_token, role = parse_token(token)
        if user_id_token and role == 'admin':
            u = User.query.get(user_id)
            if u:
                db.session.delete(u)
                db.session.commit()
                return jsonify({'message': 'User deleted successfully'})
            else:
                return jsonify({'error': 'User not found'}), 404
        else:
            return jsonify({'error': 'Invalid token or not admin'}), 401
    else:
        return jsonify({'error': 'No token provided'}), 401

@app.route('/admin/users', methods=['POST'])
def create_user():
    token = request.headers.get('Authorization')
    if token:
        user_id_token, role = parse_token(token)
        if user_id_token and role == 'admin':
            data = request.json
            new_user = User(name=data['name'], email=data['email'], password=data['password'])
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'User created successfully'})
        else:
            return jsonify({'error': 'Invalid token or not admin'}), 401
    else:
        return jsonify({'error': 'No token provided'}), 401

if __name__ == '__main__':
    app.run(debug=True)