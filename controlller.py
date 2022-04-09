from model import *
from main import db, api
from flask_restful import Api, Resource
from flask import Flask, jsonify, request
import random, string

def errorMessage(text):
    result={
        "error": text,
        "status": False
    }
    response=jsonify(result)
    response.status_code=200
    return response

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
        new_user=User(phone=phone,password=password,name=name)
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
api.add_resource(Signup, '/v1/api/signup')