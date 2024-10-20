from flask import Flask, request, jsonify,send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from flask_cors import CORS
import os
from web3 import Web3
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
app = Flask(__name__)
CORS(app)


app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://tester:qwerty@78.24.181.54/mydb'
db = SQLAlchemy(app)

UPLOAD_FOLDER_WORKER = 'profiles_photo_worker'
UPLOAD_FOLDER_EMPLOYER = 'profiles_photo_employer'
UPLOAD_FOLDER_COURSES = 'courses'
UPLOAD_FOLDER_CERTIFICATES = 'certificates'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER_WORKER'] = UPLOAD_FOLDER_WORKER
app.config['UPLOAD_FOLDER_EMPLOYER'] = UPLOAD_FOLDER_EMPLOYER
app.config['UPLOAD_FOLDER_COURSES'] = UPLOAD_FOLDER_COURSES
app.config['UPLOAD_FOLDER_CERTIFICATES'] = UPLOAD_FOLDER_CERTIFICATES
app.config['account_address'] = '0x709F89aD46fe4e20EA1262404Db64A717C7E251B'
app.config['private_key'] = '8797cbf9a2fb0a15d14ec0faa39054e13dc0878384f5794f03e2fff27198e120'

def mint_nft_func(to_address, token_uri):
    infura_url = 'https://sepolia.infura.io/v3/87e9026055e542ff8a8c95b18576746c'
    web3 = Web3(Web3.HTTPProvider(infura_url))
    to_address=Web3.to_checksum_address(to_address)
    if not web3.is_connected():
        print("Не удалось подключиться к сети Sepolia")
        exit()
    contract_address = '0x7E440aaE77D70380939449b16C2AB38CC0E6Cff0' 
    with open('MyNFT.json', 'r', encoding='utf-8') as abi_file:
        abi = json.load(abi_file)['abi']
    contract = web3.eth.contract(address=contract_address, abi=abi)

    account_address = app.config['private_key']
    private_key = app.config['private_key']

    nonce = web3.eth.get_transaction_count(account_address)
    
    txn = contract.functions.mint(to_address, token_uri).build_transaction({
    'chainId': 11155111,
    'gas': 205000,
    'gasPrice': web3.to_wei('10', 'gwei'),
    'nonce': nonce,
    })

    signed_txn = web3.eth.account.sign_transaction(txn, private_key=private_key)
    txn_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
    txn_receipt = web3.eth.wait_for_transaction_receipt(txn_hash)
    return txn_hash

def Send_data_to_blockchain(data_to_store):
    infura_url = 'https://sepolia.infura.io/v3/87e9026055e542ff8a8c95b18576746c'
    web3 = Web3(Web3.HTTPProvider(infura_url))

    if not web3.is_connected():
        raise Exception("Не удалось подключиться к сети Ethereum")

    account = app.config['private_key']
    private_key = app.config['private_key']
    
    data_json = json.dumps(data_to_store)

    nonce = web3.eth.get_transaction_count(account)
    transaction = {
        'to': account,
        'value': web3.to_wei(0, 'ether'), 
        'gas': 35120,#todo авторасчёт газа, на дальнюю полку
        'gasPrice': web3.to_wei('50', 'gwei'),
        'nonce': nonce,
        'data': web3.to_hex(text=data_json) 
    }

    signed_tx = web3.eth.account.sign_transaction(transaction, private_key)

    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)

    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Транзакция записана, хеш: {tx_hash.hex()}")
    print("test", Read_data_from_blockchain(tx_hash.hex()))
    return tx_hash.hex()
def Read_data_from_blockchain(tx_hash):
    infura_url = 'https://sepolia.infura.io/v3/87e9026055e542ff8a8c95b18576746c'
    web3 = Web3(Web3.HTTPProvider(infura_url))

    if not web3.is_connected():
        raise Exception("Не удалось подключиться к сети Ethereum")
    tx = web3.eth.get_transaction(tx_hash)

    stored_data = web3.to_text(tx['input'])

    return stored_data
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
class Users_auth5_0(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    birthDate = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
    now_work_in_company = db.Column(db.String(100))
    education = db.Column(db.String(200))
    now_pay = db.Column(db.Integer)
    about = db.Column(db.String(2000))
    job_title = db.Column(db.String(200))
    job_expirience=db.Column(db.String(200))
    total_payed = db.Column(db.Integer)
    personal_contacts = db.Column(db.String(200))
class Employers4(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(2200))
    
    address = db.Column(db.String(250), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
class Certificates_edu3(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False)
    first_step_hash = db.Column(db.String(256))
    second_step_hash = db.Column(db.String(256))
    third_step_hash = db.Column(db.String(256))
    cert_owner_org = db.Column(db.String(255), nullable=False)
class Certificates_edu8(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_email = db.Column(db.String(256), nullable=False)
    first_step_hash = db.Column(db.String(256))
    second_step_hash = db.Column(db.String(256))
    third_step_hash = db.Column(db.String(256))
    cert_owner_org_email = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(255), nullable=False)
    actuality = db.Column(db.String(255), nullable=False)
    NFT_txn = db.Column(db.String(255))
    
class Courses4(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_name = db.Column(db.String(256), nullable=False)
    course_description = db.Column(db.String(2056))
    course_creator = db.Column(db.Integer)
    course_type = db.Column(db.String(50), nullable=False)


@app.route('/register_worker', methods=['POST'])
def register_worker():
    name = request.form.get('name')
    birthDate = request.form.get('birthDate')
    email = request.form.get('email')
    phone = request.form.get('phone')
    password = request.form.get('password')
    account_type = request.form.get('account_type')

    if not email or not password or not name or not birthDate or not phone:
        return jsonify({"error": "Missing fields"}), 400
    print(request.files)
    if 'profile_image' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['profile_image']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    hashed_password = generate_password_hash(password)
    new_user = Users_auth5_0(
        name=name, 
        password_hash=hashed_password,
        birthDate=birthDate,
        email=email,
        phone=phone,
        account_type=account_type
    )

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "User already exists"}), 409
    if file and allowed_file(file.filename):
        file.save(os.path.join(app.config['UPLOAD_FOLDER_WORKER'], f"{new_user.id}.{file.filename.rsplit('.', 1)[1]}"))
    return jsonify({"message": "User registered successfully", "user_id": new_user.id}), 201
@app.route('/register_employer', methods=['POST'])
def register_employer():
    name = request.form.get('name')
    address = request.form.get('address')
    email = request.form.get('email')
    phone = request.form.get('phone')
    password = request.form.get('password')
    account_type = request.form.get('account_type')
    if 'profile_image' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['profile_image']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400


    
    if not email or not password or not name or not address or not phone:
        return jsonify({"error": "Missing username or password"}), 400

    hashed_password = generate_password_hash(password)
    new_user = Employers4(name=name, password_hash=hashed_password,address=address,email=email,phone=phone,account_type=account_type)

    try:
        db.session.add(new_user)
        db.session.commit()
        
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username already exists"}), 409

    if file and allowed_file(file.filename):
        file.save(os.path.join(app.config['UPLOAD_FOLDER_EMPLOYER'], f"{new_user.id}.{file.filename.rsplit('.', 1)[1]}"))

    return jsonify({"message": "User registered successfully", "user_id": new_user.id, "account_type":new_user.account_type}), 201
@app.route('/create_cert_edu', methods=['POST'])
def create_cert_edu():
    data = request.json
    state_edu = data.get('state_edu')
    cert_name = data.get('cert_name')
    email = data.get('email')
    giver_job_name = data.get('giver_job_name')
    giver = data.get('giver')
    if 'profile_image' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['profile_image']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400


    
    data_to_store = {
    "name": "Хуета та ещё, но вдруг",
    "description": "TEST !#*$)(!@*#(!3213123123123123123)@#*(!@#*!()#*(!@*#(&*&*(SYF(HSG*ASCHIHAXKFVF??><X>C<?/v/.vzxf,/fwt]rewt]we[]eqw[p]lf'gdcmvsknzx,mvnxmzvmv/m"
    }
    Send_data_to_blockchain(data_to_store)

    return jsonify({"message": "User registered successfully", "user_id": new_user.id, "account_type":new_user.account_type}), 201

@app.route('/create_certificate', methods=['POST'])
def create_certificate():
    # data = request.json
    cert_name = request.form.get('cert_name')
    comment = request.form.get('comment')
    course_module = request.form.get('course_module')
    reciever_email = request.form.get('reciever_email')
    sender_job_title = request.form.get('sender_job_title')
    sender_email = request.form.get('sender_email')
    arbitrator = request.form.get('arbitrator')

    if 'cert_file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['cert_file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    file_bytes = file.read()
    file_hex = file_bytes.hex()
    #todo ограничить размер файла
    # if len(file_he
    
    
    data_to_store = {
    "cert_name": cert_name,
    "comment": comment,
    "course_module": course_module,
    "reciever_email": reciever_email,
    "sender_job_title": sender_job_title,
    "sender_email": sender_email,
    "arbitrator": arbitrator,
    "file": file_hex
    }
    txn_hash = Send_data_to_blockchain(data_to_store)
    
    new_cert = Certificates_edu8(status="WAIT_FOR_ARBITR",actuality="ACTIVE",cert_owner_org_email=sender_email,third_step_hash='WAIT',second_step_hash=txn_hash,first_step_hash='NONE',owner_email=reciever_email)

    try:
        db.session.add(new_cert)
        db.session.commit()
        
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Cert already exists WTF"}), 409

    
    return jsonify({"message": "SUCCESS"}), 201
@app.route('/confirm_certificate', methods=['POST'])
def confirm_certificate():
    data = request.json
    cert_id = data.get('cert_id')
    company_id = int(data.get('company_id'))
    print(company_id)
    cert = Certificates_edu8.query.filter_by(id=cert_id).first()
    txn_hash = ''
    print(cert.first_step_hash,cert.second_step_hash,cert.third_step_hash)
    if company_id == 1:
        txn_hash = cert.second_step_hash
    else:
        txn_hash = cert.first_step_hash
    print(txn_hash)
    blockchain_data = json.loads(Read_data_from_blockchain(txn_hash))
    
    data_to_store = {
    "cert_name": blockchain_data['cert_name'],
    "comment": blockchain_data['comment'],
    "course_module": blockchain_data['course_module'],
    "reciever_email": blockchain_data['reciever_email'],
    "sender_job_title": blockchain_data['sender_job_title'],
    "sender_email": blockchain_data['sender_email'],
    "arbitrator": blockchain_data['arbitrator'],
    "file": blockchain_data['file']
    }
    if company_id == 1:
        data_to_store["Confirmed_by_Arbitr"]=True
        data_to_store["Confirmed_by_Company"]=True
    else:
        data_to_store["Confirmed_by_Arbitr"]=False
        data_to_store["Confirmed_by_Company"]=True
    print(data_to_store)
    txn_hash = Send_data_to_blockchain(data_to_store)
    if company_id == 1:
        cert.third_step_hash = txn_hash
        cert.status = "APPROVED"
    else:
        cert.second_step_hash = txn_hash
        cert.status = "WAIT_FOR_ARBITR"
    try:
        db.session.commit()
        
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Cert already exists WTF"}), 409

    
    return jsonify({"message": "SUCCESS"}), 201

@app.route('/create_course', methods=['POST'])
def create_course():
    # data = request.json
    course_description = request.form.get('course_description')
    course_creator = request.form.get('course_creator')
    course_name = request.form.get('course_name')

    if 'course_file' not in request.files or 'certificate_file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    course_file = request.files['course_file']
    certificate_file = request.files['certificate_file']

    if course_file.filename == '' or certificate_file.filename=='':
        return jsonify({"error": "No selected file"}), 400


    new_course = Courses4(course_description=course_description, course_creator=course_creator,course_name=course_name, course_type='not-required')
    try:
        db.session.add(new_course)
        db.session.commit()
        
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Course already exists"}), 409

    if course_file:
        course_file.save(os.path.join(app.config['UPLOAD_FOLDER_COURSES'], f"{new_course.id}.{course_file.filename.rsplit('.', 1)[1]}"))
    if certificate_file:
        course_file.save(os.path.join(app.config['UPLOAD_FOLDER_CERTIFICATES'], f"{new_course.id}.{certificate_file.filename.rsplit('.', 1)[1]}"))
    
    return jsonify({"message": "Course created successfully", "new_course": new_course.id}), 201

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
        user = Users_auth5_0.query.filter_by(email=email).first()
    else:
        user = Employers4.query.filter_by(email=email).first()
    if user and check_password_hash(user.password_hash, password):
        return jsonify({"message": "Login successful", "user_id": user.id}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401


@app.route('/get_company_cretificates', methods=['POST'])
def get_company_cretificates():
    data = request.json
    user_id = data.get('user_id')
    company = Employers4.query.filter_by(id=user_id).first()
    if company:
        company_email = company.email,
    else:
        return jsonify({"error": "Company not found"}), 404
    try:
        if user_id!=1:
            certificates = Certificates_edu8.query.filter_by(cert_owner_org_email=company_email).all()
        else:
            certificates = Certificates_edu8.query.filter_by(status="WAIT_FOR_ARBITR").all()
        if not certificates:
            return jsonify({"message": "No certificates found for this user"}), 404

        cert_list = []

        for cert in certificates:
            # flag = "WAIT_FOR_ARBITR"
            sec_flag=False
            third_flag=False
            if cert.status == "WAIT_FOR_ARBITR":
                txn_hash = cert.second_step_hash
                sec_flag=True
            elif cert.status == "APPROVED":
                txn_hash = cert.third_step_hash
                third_flag=True
                sec_flag=True
            else:
                txn_hash = cert.first_step_hash
            print(txn_hash)
            
            try:
                blockchain_data = json.loads(Read_data_from_blockchain(txn_hash))
                cert_list.append({
                    'id': cert.id,
                    'title': blockchain_data['cert_name'],
                    'description': blockchain_data['comment'],
                    'issuedPerson': blockchain_data['sender_email'],
                    'signatureArbitr': third_flag,
                    'signatureCompany': sec_flag,
                    'NFT': str(cert.NFT_txn).replace(r'\x','0x'),
                    
                    'transactionToken': f"0x{txn_hash}",
                    'transactionLink': f"https://sepolia.etherscan.io/tx/0x{txn_hash}"
                    
                })
            except Exception as e:
                cert_list.append({
                    'certificate_id': cert.id,
                    'txn_hash': txn_hash,
                    'blockchain_data': f"Error reading from blockchain: {str(e)}",
                    'status':cert.status
                })

        return jsonify({"certificates": cert_list}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/get_user_cretificates', methods=['POST'])
def get_user_cretificates():
    data = request.json
    user_id = data.get('user_id')
    print(user_id)
    user = Users_auth5_0.query.filter_by(id=user_id).first()
    if user:
        user_email = user.email,
    else:
        return jsonify({"error": "User not found"}), 404
    try:
        certificates = Certificates_edu8.query.filter_by(owner_email=user_email).all()

        if not certificates:
            return jsonify({"message": "No certificates found for this user"}), 404

        cert_list = []

        for cert in certificates:
            # flag = "WAIT_FOR_ARBITR"
            sec_flag=False
            third_flag=False
            if cert.status == "WAIT_FOR_ARBITR":
                txn_hash = cert.second_step_hash
                sec_flag=True
            elif cert.status == "APPROVED":
                txn_hash = cert.third_step_hash
                sec_flag=True
                third_flag=True
            else:
                txn_hash = cert.first_step_hash
            print(txn_hash)
            
            try:
                blockchain_data = json.loads(Read_data_from_blockchain(txn_hash))
                cert_list.append({
                    'id': cert.id,
                    'title': blockchain_data['cert_name'],
                    'description': blockchain_data['comment'],
                    'issuedPerson': blockchain_data['sender_email'],
                    'signatureArbitr': third_flag,
                    'signatureCompany': sec_flag,
                    'NFT': str(cert.NFT_txn).replace(r'\x','0x'),
                    
                    'transactionToken': f"0x{txn_hash}",
                    'transactionLink': f"https://sepolia.etherscan.io/tx/0x{txn_hash}"
                    
                })
            except Exception as e:
                cert_list.append({
                    'certificate_id': cert.id,
                    'txn_hash': txn_hash,
                    'blockchain_data': f"Error reading from blockchain: {str(e)}",
                    'status':cert.status
                })

        return jsonify({"certificates": cert_list}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_user_id_info', methods=['POST'])
def get_user_id_info():
    data = request.json
    user_id = data.get('id')
    account_type = data.get('account_type')
    
    if not user_id or not account_type:
        return jsonify({"error": "Missing user ID or account type"}), 400

    if account_type == "Worker":
        user = Users_auth5_0.query.filter_by(id=user_id).first()
        if user:
            user_info = {
           'id': user.id,
            'email': user.email,
            'edit-name': user.name,
            'birthday': user.birthDate,
            'phone-number': user.phone,
            'account_type': user.account_type,
            'name-company': user.now_work_in_company,
            'education': user.education,
            'worker-salary': user.now_pay,
            'about': user.about,
            'worker-post': user.job_title,
            'worker-experience': user.job_expirience,
            'worker-done-salary': user.total_payed,
            'contacts': user.personal_contacts
            }
        else:
            return jsonify({"error": "User not found"}), 404
    else:
        user = Employers4.query.filter_by(id=user_id).first()
        if user:
            user_info = {
                "id": user.id,
                "email": user.email,
                "edit-name": user.name,
                "company-address": user.address,
                "phone-number": user.phone,
                "account_type": user.account_type,
                "company-description": user.description
                
            }
            print(user_info)
        else:
            return jsonify({"error": "User not found"}), 404

    return jsonify({"user_info": user_info}), 200
@app.route('/update_user_info', methods=['POST'])
def update_user_info():
    data = request.json
    user_id = data.get('id')
    account_type = data.get('account_type')

    if not user_id or not account_type:
        return jsonify({"error": "Missing user ID or account type"}), 400

    if account_type == "Worker":
        user = Users_auth5_0.query.filter_by(id=user_id).first()
        if user:
            user.name = data.get('edit-name') or user.name
            user.email = data.get('email') or user.email
            user.birthDate = data.get('birthday') or user.birthDate
            user.phone = data.get('phone-number') or user.phone
            user.education = data.get('education') or user.education
            user.about = data.get('about') or user.about
            user.personal_contacts = data.get('contacts') or user.personal_contacts
            db.session.commit()
            return jsonify({"message": "User data updated successfully"}), 200
        else:
            return jsonify({"error": "User not found"}), 404
    elif account_type == "Employer":
        user = Employers4.query.filter_by(id=user_id).first()
        if user:
            user.name = data.get('company-name') or user.name
            user.email = data.get('company-email') or user.email
            user.phone = data.get('company-phone') or user.phone
            user.address = data.get('company-address') or user.address
            user.description = data.get('company-description') or user.address
            
            db.session.commit()
            return jsonify({"message": "Employer data updated successfully"}), 200
        else:
            return jsonify({"error": "Employer not found"}), 404
    else:
        return jsonify({"error": "Invalid account type"}), 400
@app.route('/mint_nft', methods=['POST'])
def mint_nft():
    data = request.json
    cert_id = data.get('cert_id')
    address = data.get('address')

    if not cert_id or not address:
        return jsonify({"error": "Missing cert_id or address"}), 400
    cert = Certificates_edu8.query.filter_by(id=cert_id).first()
    if cert:
        if cert.status=="APPROVED":
            txn_hash = mint_nft_func(address,f'LINK FOR NFT WITH ID {cert_id} FOR ADDRESS {address}')
            cert.NFT_txn = txn_hash or cert.NFT_txn
            db.session.commit()
            return jsonify({"message": "MINT SUCCSESSFULL"}), 200
        else:
            return jsonify({"message": "MINT SUCCSESSFULL xDDDDDDDDDD"}), 200
    else:
        return jsonify({"error": "Cert not found"}), 404


@app.route('/courses', methods=['GET'])
def get_courses():
    courses = Courses4.query.all()
    course_list = []
    for course in courses:
        course_list.append({
            'id': course.id,
            'name': course.course_name,
            'description': course.course_description,
            'creator': course.course_creator,
            'type': course.course_type
        })
    
    return jsonify({"courses": course_list}), 200
@app.route('/employers_list', methods=['GET'])
def employers_list():
    employers = Employers4.query.all()
    employers_lst = []
    for employer in employers:
        employers_lst.append({
            'id': employer.id,
            'title': employer.name,
            'description': employer.description,
            'contactInfo': employer.phone,
            'Email': employer.email
        })
    
    return jsonify({"employers": employers_lst}), 200
@app.route('/workers_list', methods=['GET'])
def workers_list():
    employers = Users_auth5_0.query.filter_by(now_work_in_company=None).all()
    employers_lst = []
    for employer in employers:
        employers_lst.append({
            'id': employer.id,
            'title': employer.name,
            'description': employer.about,
            'contactInfo': employer.phone,
            'Email': employer.email
        })
    
    return jsonify({"workers": employers_lst}), 200
@app.route('/workers_in_company_list/<int:company_id>', methods=['GET'])
def workers_in_company_list(company_id):
    employers = Users_auth5_0.query.filter_by(now_work_in_company=str(company_id)).all()
    employers_lst = []
    for employer in employers:
        employers_lst.append({
            'id': employer.id,
            'title': employer.name,
            'description': employer.about,
            'contactInfo': employer.phone,
            'Email': employer.email
        })
    
    return jsonify({"workers": employers_lst}), 200
# @app.route('/certs_to_confirm/<int:company_id>', methods=['GET'])
# def certs_to_confirm(company_id):
    # if company_id != 1:
        # certs = Certificates_edu8.query.filter_by(now_work_in_company=str(company_id)).all()
    # else:
        
    # employers_lst = []
    # for employer in employers:
        # employers_lst.append({
            # 'id': employer.id,
            # 'title': employer.name,
            # 'description': employer.about,
            # 'contactInfo': employer.phone,
            # 'Email': employer.email
        # })
    
    # return jsonify({"workers": employers_lst}), 200

@app.route('/recruit_worker', methods=['POST'])
def recruit_worker():
    data = request.json
    user_id = data.get('user_id')
    company_id = data.get('company_id')
    user = Users_auth5_0.query.filter_by(id=user_id).first()
    if user:
        user.now_work_in_company = data.get('company_id')
        db.session.commit()
    return jsonify("OK"), 200

@app.route('/get_profile_image/<int:user_id>', methods=['GET'])
def get_profile_image(user_id):
    folder = app.config['UPLOAD_FOLDER_WORKER'] if user_id in [user.id for user in Users_auth5_0.query.all()] else app.config['UPLOAD_FOLDER_EMPLOYER']
    for filename in os.listdir(folder):
        if filename.startswith(f"{user_id}."):
            return send_from_directory(folder, filename)

    return jsonify({"error": "Image not found"}), 404
@app.route('/upload_profile_image/<int:user_id>', methods=['POST'])
def upload_profile_image(user_id):
    if 'image' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['image']
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file:
        ext = file.filename.rsplit('.', 1)[1].lower()
        folder = app.config['UPLOAD_FOLDER_WORKER'] if user_id in [user.id for user in Users_auth5_0.query.all()] else app.config['UPLOAD_FOLDER_EMPLOYER']
        filename = f"{user_id}.{ext}"
        for existing_file in os.listdir(folder):
            if existing_file.startswith(f"{user_id}."):
                os.remove(os.path.join(folder, existing_file))
        file.save(os.path.join(folder, filename))
        return jsonify({"message": "Image uploaded successfully"}), 200
    
    return jsonify({"error": "File upload failed"}), 500
if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True,port=8092,host='0.0.0.0')
