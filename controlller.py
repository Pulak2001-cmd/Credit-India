from model import *
from main import db, api, FERNET_KEY
from flask_restful import Api, Resource
from flask import Flask, jsonify, request, Response
from sqlalchemy import and_
import random, string, bcrypt
from functools import wraps


class User(db.Model):
    __tablename__="users"
    id=db.Column(db.Integer, primary_key=True, autoincrement=True)
    name=db.Column("name", db.String(50), default=None)
    phone=db.Column("phone",db.String(15),default=None)
    email=db.Column("email",db.String(50),default=None)
    password=db.Column("password",db.String(500),default=None)
    is_delete=db.Column("is_delete",db.Boolean,default=0)
    wallet=db.Column("wallet",db.Integer,default=0)
    
class Session(db.Model):
    __tablename__="session"
    id=db.Column(db.Integer, primary_key=True, autoincrement=True)
    token=db.Column(db.String,primary_key=True)
    user_id=db.Column(db.String,primary_key=True)
    is_delete=db.Column("is_delete",db.Boolean,default=0)
    user = db.relationship('User', foreign_keys=user_id,
                           primaryjoin="Session.user_id==User.id")

def get_hashed_password(plain_text_password):
    # Hash a password for the first time
    #   (Using bcrypt, the salt is saved into the hash itself)
    plain_text_password = bytes(plain_text_password, 'utf-8')
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())

def check_password(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    plain_text_password = bytes(plain_text_password, 'utf-8')
    hashed_password = bytes(hashed_password, 'utf-8')
    return bcrypt.checkpw(plain_text_password, hashed_password)

def errorMessage(text):
    result={
        "error": text,
        "status": False
    }
    response=jsonify(result)
    response.status_code=200
    return response

def authenticate_api(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            authtoken = request.headers['authtoken']
        except:
            return Response('Authentication Error! Auth Token is missing', 401, {'WWW-Authenticate': 'API token error'})
        authObj = Session.query.filter(and_(Session.token == authtoken, Session.is_delete == 0)).first()
        # print(authObj)
        if not authObj:
            return Response('Authentication Error! Token is invalid or does not belong to the user', 401,
                            {'WWW-Authenticate': 'API token error'})
        kwargs['session'] = authObj
        kwargs['user'] = authObj.user
        return f(*args, **kwargs)

    return wrapper
class hello(Resource):
    def get(self):
        result = {"msg": "how"}
        return jsonify(result)

class Signup(Resource):
    def post(self):
        data=request.get_json()
        if "phone" in data.keys():
            phone=data["phone"]
            phone = "+91"+str(phone)
        else:
            return errorMessage("phone number is required")

        if "password" in data.keys():
            password=data["password"]
        else:
            return errorMessage("password is required")
        if "name" in data.keys():
            name=data["name"]
        else:
            return errorMessage("name is required")
        if "email" in data.keys():
            email=data["email"]
        else:
            return errorMessage("email is required")
        get_user_by_email = User.query.filter(and_(User.email == email, User.is_delete == 0)).first()
        get_user_by_phone = User.query.filter(and_(User.phone == phone, User.is_delete == 0)).first()
        if get_user_by_phone is not None or get_user_by_email is not None:
            return errorMessage("Your credentials already exists")
        en_pass = get_hashed_password(password)
        new_user=User(phone=phone,password=en_pass,name=name, email=email)
        db.session.add(new_user)
        db.session.commit()
        token=''.join(random.choices(
            string.ascii_uppercase+string.digits,k=50))
        new_session=Session(user_id=new_user.id,token=token)
        print(new_user.password)
        db.session.add(new_session)
        db.session.commit()
        result={
            "error":"",
            "status":True,
            "Token":token
        }
        response=jsonify(result)
        response.status_code=200
        return response

class LoginWithPassword(Resource):
    def post(self):
        data = request.get_json()
        if "user_details" in data.keys():
            user_details = data["user_details"]
        else:
            return errorMessage("user_details is required")
        if "password" in data.keys():
            password = data["password"]
        else:
            return errorMessage("password is required")
        token=''.join(random.choices(
            string.ascii_uppercase+string.digits,k=50))
        search_user = User.query.filter(and_(User.email == user_details, User.is_delete == 0)).first()
        if search_user is None:
            search_user = User.query.filter(and_(User.phone == "+91"+ str(user_details), User.is_delete == 0)).first()
        if search_user is None:
            return errorMessage("User does not exists")
        password_decode = ""
        if search_user.password is not None:
            password_decode = check_password(password, search_user.password)
        if password_decode == True:
            new_session = Session(user_id = search_user.id, token=token)
            db.session.add(new_session)
            db.session.commit()
        else:
            return errorMessage("Wrong Password")
        result = {
            "error": "",
            "status": True,
            "name": search_user.name,
            "phone": search_user.phone,
            "email": search_user.email,
            "token": token
        }
        return jsonify(result)

class Logout(Resource):
    @authenticate_api
    def get(self, **kwargs):
        session = kwargs['session']
        get_session = Session.query.filter(and_(Session.id == session.id, Session.is_delete == 0)).first()
        print(get_session)
        db.session.delete(get_session)
        db.session.commit()
        result = {
            "error": "",
            "status": True
        }
        return jsonify(result)

class LoginWithAccount(Resource):
    def post(self):
        data = request.get_json()
        if "email" in data.keys():
            email = data["email"]
        else:
            return errorMessage("email is required")
        if "name" in data.keys():
            name = data["name"]
        else:
            name= None
        token=''.join(random.choices(
            string.ascii_uppercase+string.digits,k=50))
        get_user = User.query.filter(and_(User.email == email, User.is_delete == 0)).first()
        if get_user is not None:
            new_session = Session(token=token, user_id=get_user.id)
            db.session.add(new_session)
            db.session.commit()
            result = {
                "error": "",
                "status": True,
                "name": get_user.name,
                "phone": get_user.phone,
                "email": get_user.email,
                "token": token
            }
            return jsonify(result)
        else:
            add_user = User(email=email, name=name)
            db.session.add(add_user)
            db.session.commit()
            new_session = Session(user_id = add_user.id, token=token)
            db.session.add(new_session)
            db.session.commit()
            result = {
                "error": "",
                "status": True,
                "name": add_user.name,
                "email": add_user.email,
                "token": token
            }
            return jsonify(result)

class ProfileInfo(Resource):
    @authenticate_api
    def get(self, **kwargs):
        user = kwargs["user"]
        result = {
            "id": user.id,
            "name": user.name,
            "phone": user.phone,
            "email": user.email
        }
        return jsonify(result)

class UpdateProfile(Resource):
    @authenticate_api
    def post(self, **kwargs):
        user = kwargs["user"]
        data = request.get_json()
        if "user_name" in data.keys():
            name = data["user_name"]
        else:
            name = None
        if name is not None:
            user.name = name
            db.session.add(user)
            db.session.commit()
        result = {
            "error": "",
            "status": True
        }
        return jsonify(result)


api.add_resource(Signup, '/v1/api/signup')
api.add_resource(LoginWithPassword, '/v1/api/loginwithpass')
api.add_resource(Logout, '/v1/api/logout')
api.add_resource(LoginWithAccount, '/v1/api/o_login')
api.add_resource(ProfileInfo, '/v1/api/profile')
api.add_resource(UpdateProfile, '/v1/api/updateprofile')