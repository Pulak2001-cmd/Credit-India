from model import *
from main import db, api, FERNET_KEY
from flask_restful import Api, Resource
from flask import Flask, jsonify, request, Response
from cryptography.fernet import Fernet
from sqlalchemy import and_
import random, string
from functools import wraps

class User(db.Model):
    __tablename__="users"
    id=db.Column(db.Integer, primary_key=True, autoincrement=True)
    name=db.Column("name", db.String(50), default=None)
    phone=db.Column("phone",db.String(15),default=None)
    email=db.Column("email",db.String(50),default=None)
    password=db.Column("password",db.String(50),default=None)
    is_delete=db.Column("is_delete",db.Boolean,default=0)
    wallet=db.Column("wallet",db.Integer,default=0)
    
class Session(db.Model):
    __tablename__="session"
    id=db.Column(db.Integer, primary_key=True, autoincrement=True)
    token=db.Column(db.String,primary_key=True)
    user_id=db.Column(db.String,primary_key=True)
    is_delete=db.Column("is_delete",db.Boolean,default=0)

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
        print(authObj)
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
        fernet=Fernet(FERNET_KEY)
        en_pass=fernet.encrypt(bytes(password,'utf-8'))
        new_user=User(phone=phone,password=en_pass,name=name)
        db.session.add(new_user)
        db.session.commit()
        token=''.join(random.choices(
            string.ascii_uppercase+string.digits,k=50))
        new_session=Session(user_id=new_user.id,token=token)
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
        search_user = User.query.filter(and_(User.email == user_details, User.is_delete == 0))

api.add_resource(Signup, '/v1/api/signup')
api.add_resource(hello, '/v1/api/hello')