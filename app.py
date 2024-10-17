from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://tester:qwerty@78.24.181.54/mydb'
db = SQLAlchemy(app)


class Users_auth2_0(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    birthDate = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
class Employers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(250), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)


@app.route('/register_worker', methods=['POST'])
def register_worker():
    data = request.json

    name = data.get('name')
    birthDate = data.get('birthDate')
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')
    account_type = data.get('account_type')
    

    if not email or not password or not name or not birthDate or not phone:
        return jsonify({"error": "Missing username or password"}), 400

    hashed_password = generate_password_hash(password)

    new_user = Users_auth2_0(name=name, password_hash=hashed_password,birthDate=birthDate,email=email,phone=phone,account_type=account_type)

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({"message": "User registered successfully", "user_id": new_user.id, "account_type":new_user.account_type}), 201
@app.route('/register_employer', methods=['POST'])
def register_employer():
    data = request.json
    # print(data)
    # return '200'
    name = data.get('name')
    address = data.get('address')
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')
    account_type = data.get('account_type')
    

    if not email or not password or not name or not address or not phone:
        return jsonify({"error": "Missing username or password"}), 400

    hashed_password = generate_password_hash(password)
    new_user = Employers(name=name, password_hash=hashed_password,address=address,email=email,phone=phone,account_type=account_type)

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({"message": "User registered successfully", "user_id": new_user.id, "account_type":new_user.account_type}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    account_type = data.get('account_type')
    INN = data.get('INN')
    
    if not email or not password:
        return jsonify({"error": "Missing username or password"}), 400
    if account_type=="Worker":
        user = Users_auth2_0.query.filter_by(email=email).first()
    else:
        user = Employers.query.filter_by(email=email).first()
    if user and check_password_hash(user.password_hash, password):
        return jsonify({"message": "Login successful", "user_id": user.id}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True,port=8092,host='0.0.0.0')
