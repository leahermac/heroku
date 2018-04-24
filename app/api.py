from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask import render_template, request, url_for,redirect,send_from_directory
from sqlalchemy import *
from models import *
from app import *
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash
import sys, flask

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
# app = Flask(__name__)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:walakokahibaw@localhost/db'
# app.config['SECRET_KEY'] = 'hard to guess string'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# db = SQLAlchemy(app)
#retrieve data for parent,child and teacher

@app.route('/api/user/<acc_id>', methods=['GET'])
def getoneuser(acc_id):
    user = Account.query.filter_by(acc_id=acc_id).first()
    if not user:
        return jsonify({'message': "no user found"})
    user_data = {}
    user_data['acc_id'] = user.acc_id
    user_data['username'] = user.username
    user_data['email'] = user.email
    user_data['acc_type'] = user.acc_type
    return jsonify({'user': user_data})

@app.route('/api/teacher/<acc_id>', methods=['GET'])
def getinfoteacher(acc_id):
    user = Teacher.query.filter_by(acc_id=acc_id).first()
    if not user:
        return jsonify({'message': "no user found"})
    user_data = {}
    user_data['fname_t'] = user.fname_t
    user_data['lname_t'] = user.lname_t
    user_data['bday_t'] = user.bday_t
    user_data['specialty'] = user.specialty
    user_data['tel_num'] = user.tel_num
    user_data['add_t'] = user.add_t
    return jsonify({'user': user_data})

@app.route('/api/parent/<acc_id>', methods=['GET'])
def getinfoparent(acc_id):
    user = Parent.query.filter_by(acc_id=acc_id).first()
    if not user:
        return jsonify({'message': "no user found"})
    user_data = {}
    user_data['fname_p'] = user.fname_p
    user_data['lname_p'] = user.lname_p
    user_data['bday_p'] = user.bday_p
    user_data['add_p'] = user.add_p
    return jsonify({'user': user_data})

@app.route('/api/child/<c_id>', methods=['GET'])
def getinfochild(c_id):
    user = Child.query.filter_by(c_id=c_id).first()
    if not user:
        return jsonify({'message': "no user found"})
    user_data = {}
    user_data['fname_c'] = user.fname_c
    user_data['lname_c'] = user.lname_c
    user_data['bday_c'] = user.bday_c
    user_data['diagnosis'] = user.diagnosis
    return jsonify({'user': user_data})

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token= request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing'}),
        try:
            data = jwt.decode(token), app.config['SECRET_KEY']
            current_user = Account.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args,**kwargs)
    return decorated

    #edit profile -----------------------------

@app.route('/api/parent/editprofile/<int:acc_id>', methods=['POST']) #this api is for editing parent's profile 
def update_parentinfo(acc_id):
# @token_required
    Parent.query.filter_by(acc_id=int(acc_id)).first()
    data = request.get_json()

    output = Parent(fname_p = data['fname_p'], lname_p = data['lname_p'], bday_p = data['bday_p'], add_p = data['add_p'])

    output = db.session.merge(output)
    db.session.add(output)
    db.session.commit()
    return jsonify({'message' : 'success!'})


@app.route('/api/child/editprofile/<int:c_id>', methods=['POST']) #this api is for editing child's profile
def update_childinfo(c_id):
# @token_required
    Child.query.filter_by(acc_id=int(c_id)).first()
    data = request.get_json()

    output = Child(fname_c = data['fname_c'], lname_c = data['lname_c'], bday_c = data['bday_c'], diagnosis = data['diagnosis'])

    output = db.session.merge(output)
    db.session.add(output)
    db.session.commit()
    return jsonify({'message' : 'success!'})

@app.route('/api/teacher/editprofile/<int:acc_id>', methods=['POST']) #this api is for editing teacher's profile
def update_teacherinfo(c_id):
# @token_required
    Teacher.query.filter_by(acc_id=int(c_id)).first()
    data = request.get_json()

    output = Teacher(fname_t = data['fname_t'], lname_t = data['lname_t'], bday_t = data['bday_c'], specialty = data['specialty'],tel_num = data['tel_num'], add_t = data['add_t'])

    output = db.session.merge(output)
    db.session.add(output)
    db.session.commit()
    return jsonify({'message' : 'success!'})

@app.route('/api/signup', methods=['POST'])
def createuser():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_acc = Account(acc_type=data['acc_type'], username = data['username'],email=data['email'], password = hashed_password)
    print(hashed_password)

    db.session.add(new_acc)
    db.session.commit()
    return jsonify({'message' : 'New user created.'})

@app.route('/api/login', methods=['POST'])
def login_api():

    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('un authenticated', 401, {'WWW-Authenticate' : 'Login required'})
    user = Account.query.filter_by(username=auth.username).first()

    if not user:
        return jsonify('User not found', 401, {'WWW-Authenticate' : 'Login required'})

    if check_password_hash(user.password,auth.password):
        token = jwt.encode({'account_id': Account.acc_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'status': 'ok', 'token': token.decode('UTF-8')})
    return make_response('Could not verify', {'WWW-Authenticate' : 'Login required'})

@app.after_request
def after_request(response):
  response.headers.add('Access-Control-Allow-Origin', 'http://127.0.0.1:5000')
  response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
  return response