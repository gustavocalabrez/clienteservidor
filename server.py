from flask import Flask, request, jsonify, make_response, render_template
from flask_sqlalchemy import SQLAlchemy
import psycopg2
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'ProjetoCliente'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://lbvqgqvznmjiga:38073c5210e934495c697ca6a1f3a292fb8141bc438bffd22dda277a9d557b7c@ec2-52-207-25-133.compute-1.amazonaws.com:5432/d3u9feds5198d3'

db = SQLAlchemy(app)

global token_g
token_g = ''

class cliente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50))
    password = db.Column(db.String(80))
    zip_code = db.Column(db.String(8))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    city = db.Column(db.String(40))
    neighborhood = db.Column(db.String(40))
    street = db.Column(db.String(40))
    number = db.Column(db.Integer)
    complement = db.Column(db.String(40))
    phone = db.Column(db.String(15))
    role = db.Column(db.Boolean)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return make_response('No token', 401)

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = cliente.query.filter_by(id=data['id']).first()
        except:
            return make_response('Except Token', 401)

        return f(current_user, *args, **kwargs)

    return decorated
    
@app.route('/user', methods=['POST'])
def create_user():

    data = request.get_json()
    if not data or data['name'] == '' or data['password'] == '' or data['email'] == '' or data['zip_code'] == '' or data['latitude'] == 0.0 or data['longitude'] == 0.0 or data['city'] == '' or data['neighborhood'] == '' or data['street'] == '' or data['number'] == 0 or data['phone'] == '':
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif status_email(data['email']) == True:
        return make_response('', 409)
        
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = cliente(name=data['name'],
                    password=hashed_password,
                    email=data['email'],
                    role=True,
                    zip_code=data['zip_code'],
                    latitude=data['latitude'],
                    longitude=data['longitude'],
                    city=data['city'],
                    neighborhood=data['neighborhood'],
                    street=data['street'],
                    number=data['number'],
                    complement=data['complement'],
                    phone=data['phone']
                    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'Novo usuário criado!'})

@app.route('/get_token', methods=['GET'])
def get_token():
    global token_g
    print(token_g)
    return token_g

@app.route('/login', methods=['POST'])
def login():
    global token_g
    auth = request.authorization()
    if not auth or not auth.username or not auth.password:
        return make_response('', 401)
    
    user = cliente.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('', 401)
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'id':user.id, 'name': user.name}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    return make_response('', 401)
    
def status_email(eMail):
    check_mail = cliente.query.filter_by(email=eMail).first()
    if not check_mail:
        return False
    elif eMail == check_mail.email:
        return True
    return False

@app.route('/me', methods=['POST'])
@token_required
def get_one_user(user):
    user_data = {}
    user_data['id'] = user.id
    user_data['name'] = user.name
    user_data['zip_code'] = user.zip_code
    user_data['latitude'] = user.latitude
    user_data['longitude'] = user.longitude
    user_data['city'] = user.city
    user_data['neighborhood'] = user.neighborhood
    user_data['street'] = user.street
    user_data['number'] = user.number
    user_data['complement'] = user.complement
    user_data['phone'] = user.phone
    if user.role == True:
        user_data['role'] = 'user'
    else:
        user_data['role'] = 'admin'
        
    return jsonify({'user' : user_data})

@app.route('/user', methods=['PUT'])
@token_required
def update_usuario(user):
    
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    user.name=data['name'],
    user.password=hashed_password
    user.email=data['email']
    user.zip_code=data['zip_code']
    user.latitude=data['latitude']
    user.longitude=data['longitude']
    user.city=data['city']
    user.neighborhood=data['neighborhood']
    user.street=data['street']
    user.number=data['number']
    user.complement=data['complement']
    user.phone=data['phone']

    db.session.commit()

    return jsonify(), 200

if __name__ == '__main__':
    
    port = int(os.environ.get('PORT', 33507)) 
    app.run(host='0.0.0.0', port=port, use_reloader=False)
    

