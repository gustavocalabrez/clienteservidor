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
import os
import random
import string
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


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
    role = db.Column(db.Boolean)

class ocorrencia(db.Model):
    _id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(100))
    zip_code = db.Column(db.String(50))
    street = db.Column(db.String(80))
    type = db.Column(db.String(40))
    ocurred_at = db.Column(db.DateTime)
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

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/create', methods=['POST'])
def create_ocurrence():
    data = request.get_json()
    if not data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'type' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'ocurred_at' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'user_id' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'zip_code' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'latitude' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'longitude' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'city' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'neighborhood' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'street' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'anonymous' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'description' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)

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
                    user_id = data['user_id']
                    )

    db.session.add(ocurred)
    db.session.commit()

    get_all_ocurrence()
    
    return make_response('', 201)
    
@app.route('/user', methods=['POST'])
def create_user():

    data = request.get_json()
    
    if not data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'name' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'password' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'email' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'zip_code' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'latitude' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'longitude' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'city' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'neighborhood' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'street' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'number' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif not 'phone' in data:
        return make_response('Campos obrigatórios não preenchidos!', 400)
    elif status_email(data['email']) == True:
        return make_response('', 409)
        
    if data['name'] == '':
        return make_response('Campos obrigatórios não preenchidos!',400)
    elif data['password'] == '':
        return make_response('Campos obrigatórios não preenchidos!',400)
    elif data['email'] == '':
        return make_response('Campos obrigatórios não preenchidos!',400)
    elif data['zip_code'] == '':
        return make_response('Campos obrigatórios não preenchidos!',400)
    elif data['latitude'] == '' or data['latitude'] == 0.0:
        return make_response('Campos obrigatórios não preenchidos!',400)
    elif data['longitude'] == '' or data['longitude'] == 0.0:
        return make_response('Campos obrigatórios não preenchidos!',400)
    elif data['city'] == '':
        return make_response('Campos obrigatórios não preenchidos!',400)
    elif data['neighborhood'] == '':
        return make_response('Campos obrigatórios não preenchidos!',400)
    elif data['street'] == '':
        return make_response('Campos obrigatórios não preenchidos!',400)
    elif data['number'] == '' or data['number'] == 0:
        return make_response('Campos obrigatórios não preenchidos!',400)
    elif data['phone'] == '':
        return make_response('Campos obrigatórios não preenchidos!',400)
    

   
    new_user = cliente(name=data['name'],
                    password=data['password'],
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
        token = jwt.encode({'_id':user._id, 'name': user.name}, app.config['SECRET_KEY'])
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
def get_one_user(user):
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
def update_usuario(user):
    
    data = request.get_json()
    user.name=data['name']
    user.email=data['email']
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

def get_all_ocurrence():
    ocurred = ocorrencia.query.all()
    for i in ocurred:
        print(i)

@app.route('/email', methods=['GET'])
def send_email():
   data = request.get_json()
   user = cliente.query.filter_by(email=data['email']).first()

   if not user:
       return make_response('', 401)

   user.password = get_random_string()
   db.session.commit()

   gmail_user = 'projeto.utfpr.cliente@gmail.com'
   gmail_password = '321garbuio'

   sent_from = gmail_user
   to = [data['email']]
   subject = 'ALTERACAO DE SENHA - PROJETO CLIENTE SERVIDOR'
   body = "Ola usuario "+user.name+"!\n\n Sua senha foi alterada para: "+user.password

   email_text = """\
   From: %s
   To: %s
   Subject: %s

   %s
   """ % (sent_from, ", ".join(to), subject, body)

   try:
       server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
       server.ehlo()
       server.login(gmail_user, gmail_password)
       server.sendmail(sent_from, to, email_text)
       server.close()
   except:
       print("Erro")

   return make_response(body, 200)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 33507)) 
    app.run(host='0.0.0.0', port=port, use_reloader=False)
