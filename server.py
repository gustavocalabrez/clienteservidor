from flask import Flask, request, jsonify, make_response, render_template
from flask_sqlalchemy import SQLAlchemy
import psycopg2
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os
import json
from flask_cors import CORS
import sendgrid
import os
from sendgrid.helpers.mail import *
import random
import string
import smtplib
import datetime
import requests

global API_MAILGUN

API_MAILGUN = os.environ['API_MAILGUN']


def get_random_string():
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(10))
    return result_str


app = Flask(__name__)
CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SECRET_KEY'] = 'ProjetoCliente'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://lbvqgqvznmjiga:38073c5210e934495c697ca6a1f3a292fb8141bc438bffd22dda277a9d557b7c@ec2-52-207-25-133.compute-1.amazonaws.com:5432/d3u9feds5198d3'

db = SQLAlchemy(app)

class cliente(db.Model):
    _id = db.Column(db.Integer, primary_key=True)
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
    role = db.Column(db.String(15))

class ocorrencia(db.Model):
    _id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(100))
    zip_code = db.Column(db.String(50))
    street = db.Column(db.String(80))
    type = db.Column(db.String(40))
    ocurred_at = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    anonymous = db.Column(db.Boolean)
    neighborhood = db.Column(db.String(40))
    latitude = db.Column(db.Float)
    number = db.Column(db.Integer)
    complement = db.Column(db.String(40))
    longitude = db.Column(db.Float)
    city = db.Column(db.String(50))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization']

        if not token:
            return make_response('No token', 401)

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = cliente.query.filter_by(_id=data['_id']).first()
        except:
            return make_response('Except Token', 401)

        return f(current_user, data['role'], *args, **kwargs)

    return decorated

@app.route('/ocurrences/<ocurrence_id>', methods=['GET'])
@token_required
def get_ocurrence(user, role, ocurrence_id):
    pass
@app.route('/ocurrences/me', methods=['GET'])
@token_required
def get_ocurrence_me(user, role):
    print(user.email)
    ocorrencias = ocorrencia.query.filter_by(user_id = user._id]).all()
    if not ocorrencias:
        return make_response('Não temos ocorrencias com este usuario', 404)
    for i in ocorrencias:
        print(i)
    return make_response('',200)
@app.route('/ocurrences', methods=['POST', 'GET'])
@token_required
def create_ocurrence(user, role):
    if request.method == 'POST':
        data = request.get_json()
        error = 0
        response = 'Campos obrigatórios não preenchidos em: '
        if not 'type' in data:
            error = 1
            response += 'type '
        if not 'ocurred_at' in data:
            error = 1
            response += 'ocurred_at '
        if not 'zip_code' in data:
            error = 1
            response += 'zip_code '
        if not 'latitude' in data:
            error = 1
            response += 'latitude '
        if not 'longitude' in data:
            error = 1
            response += 'longitude '
        if not 'city' in data:
            error = 1
            response += 'city '
        if not 'neighborhood' in data:
            error = 1
            response += 'neighborhood '
        if not 'street' in data:
            error = 1
            response += 'street '
        if not 'anonymous' in data:
            error = 1
            response += 'anonymous '
        if not 'description' in data:
            error = 1
            response += 'description '
        if error == 1:
            return jsonify({'error':response}), 400

        if data['type'] == '':
            error = 1
            response += 'type '
        if data['ocurred_at'] == '':
            error = 1
            response += 'ocurred_at '
        if data['zip_code'] == '':
            error = 1
            response += 'zip_code '
        if data['latitude'] == '' or data['latitude'] == 0:
            error = 1
            response += 'latitude '
        if data['longitude'] == ''or data['longitude'] == 0:
            error = 1
            response += 'longitude '
        if data['city'] == '':
            error = 1
            response += 'city '
        if data['neighborhood'] == '':
            error = 1
            response += 'neighborhood '
        if data['street'] == '':
            error = 1
            response += 'street '
        if data['anonymous'] == '':
            error = 1
            response += 'anonymous '
        if data['description'] == '':
            error = 1
            response += 'description '
        if error == 1:
            return jsonify({'error':response}), 400

        ocurred = ocorrencia(type=data['type'],
                        zip_code=data['zip_code'],
                        latitude=data['latitude'],
                        longitude=data['longitude'],
                        city=data['city'],
                        neighborhood=data['neighborhood'],
                        street=data['street'],
                        number=data['number'],
                        complement=data['complement'],
                        ocurred_at=data['ocurred_at'],
                        description=data['description'],
                        anonymous=data['anonymous'],
                        user_id = user._id
                        )

        db.session.add(ocurred)
        db.session.commit()
        
        return make_response('', 201)
    elif request.method == 'GET':
        ocurred = ocorrencia.query.all()
        all_data = []
        for i in ocurred:
            user_data = {}
            user_data['_id'] = i._id
            user_data['type'] = i.type
            user_data['zip_code'] = i.zip_code
            user_data['latitude'] = i.latitude
            user_data['longitude'] = i.longitude
            user_data['city'] = i.city
            user_data['neighborhood'] = i.neighborhood
            user_data['street'] = i.street
            user_data['number'] = i.number
            user_data['complement'] = i.complement
            user_data['ocurred_at'] = i.ocurred_at
            user_data['description'] = i.description
            user_data['anonymous'] =  i.anonymous
            if i.anonymous == False:
                user_d = cliente.query.filter_by(_id=i.user_id).first()
                if not user_d:
                    return make_response('Usuário não existe',400)
                user_data['user_name'] = user_d.name
                user_data['user_id'] = i.user_id
            all_data.append(user_data)
        return jsonify(all_data)
    
@app.route('/user', methods=['POST'])
def create_user():

    data = request.get_json()

    error = 0
    response = 'Campos obrigatórios não preenchidos em: '
    if not 'name' in data:
        error = 1
        response += 'name '
    if not 'password' in data:
        error = 1
        response += 'password ' 
    if not 'email' in data:
        error = 1
        response += 'email '        
    if not 'zip_code' in data:
        error = 1
        response += 'zip_code '        
    if not 'latitude' in data:
        error = 1
        response += 'latitude '        
    if not 'longitude' in data:
        error = 1
        response += 'longitude '        
    if not 'city' in data:
        error = 1
        response += 'city '        
    if not 'neighborhood' in data:
        error = 1
        response += 'neighborhood '        
    if not 'street' in data:
        error = 1
        response += 'street '        
    if not 'number' in data:
        error = 1
        response += 'number '       
    if not 'phone' in data:
        error = 1
        response += 'phone '        

    if error == 1:
        return jsonify({'error':response}), 400
    
    if status_email(data['email']) == True:
        return jsonify({'error':response}), 400
        
    if data['name'] == '':
        error = 1
        response += 'name '
    if data['password'] == '':
        error = 1
        response += 'password '
    if data['email'] == '':
        error = 1
        response += 'email ' 
    if data['zip_code'] == '':
        error = 1
        response += 'zip_code '
    if data['latitude'] == '' or data['latitude'] == 0.0:
        error = 1
        response += 'latitude '
    if data['longitude'] == '' or data['longitude'] == 0.0:
        error = 1
        response += 'longitude '
    if data['city'] == '':
        error = 1
        response += 'city '
    if data['neighborhood'] == '':
        error = 1
        response += 'neighborhood '
    if data['street'] == '':
        error = 1
        response += 'street '
    if data['number'] == '' or data['number'] == 0:
        error = 1
        response += 'number ' 
    if data['phone'] == '':
        error = 1
        response += 'phone '
    if error == 1:
        return jsonify({'error':response}), 400

   
    new_user = cliente(name=data['name'],
                    password=data['password'],
                    email=data['email'],
                    role="user",
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

    return  make_response('', 201)

@app.route('/get_token', methods=['GET'])
def get_token():
    global token_g
    return token_g

@app.route('/login', methods=['POST'])
def login():
    global token_g
    auth = request.get_json()
    
    
    if not auth or not auth['email'] or not auth['password']:
        return make_response('', 401)
    
    user = cliente.query.filter_by(email=auth['email']).first()

    if not user:
        return make_response('', 401)
    
    if user.password == auth['password']:
        token = jwt.encode({'_id':user._id, 'name': user.name, 'role':user.role}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    return make_response('', 401)
    
def status_email(eMail):
    check_mail = cliente.query.filter_by(email=eMail).first()
    if not check_mail:
        return False
    elif eMail == check_mail.email:
        return True
    return False

@app.route('/me', methods=['GET'])
@token_required
def get_one_user(user, role):
    user_data = {}
    user_data['_id'] = user._id
    user_data['name'] = user.name
    #user_data['password'] = user.password
    user_data['email'] = user.email
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
        
    return jsonify(user_data)

@app.route('/user', methods=['PUT'])
@token_required
def update_usuario(user, role):
    
    data = request.get_json()
    user.name=data['name']
    user.email=data['email']
    if data['password'] != '':
        user.password=data['password']
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

    return make_response('', 200)

@app.route('/email', methods=['post'])
def send_email():
    global API_MAILGUN
    data = request.get_json()
    user = cliente.query.filter_by(email=data['email']).first()

    if not user:
        return make_response('', 401)
    
    user.password = get_random_string()
    db.session.commit()
    print(API_MAILGUN)
    requests.post( "https://api.mailgun.net/v3/sandbox53ca05e8db7d4f85a7d2fb33de8302f9.mailgun.org/messages", auth=("api", API_MAILGUN), data={"from": "Mailgun Sandbox <postmaster@sandbox53ca05e8db7d4f85a7d2fb33de8302f9.mailgun.org>", "to": "GUSTAVO TADEU MIRANDA CALABREZ <gustavo.calabrez@gmail.com>", "subject": "Hello GUSTAVO TADEU MIRANDA CALABREZ", "text": "Congratulations GUSTAVO TADEU MIRANDA CALABREZ, you just sent an email with Mailgun!  You are truly awesome!"})
    return make_response('',200)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 33507)) 
    app.run(host='0.0.0.0', port=port, use_reloader=False)
