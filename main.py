import random
import string
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask_cors import CORS, cross_origin

app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY'] = "Super Secret Key"
CORS(app, resources={r"/v1/*": {"origins":"*"}})
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:@localhost/indiacredit"
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__="users"
    id=db.Column(db.Integer, primary_key=True)
    name=db.Column("name", db.String(50), default=None)
    phone=db.Column("phone",db.String(15),default=None)
    email=db.Column("email",db.String(50),default=None)
    password=db.Column("password",db.String(50),default=None)
    is_delete=db.Column("is_delete",db.Boolean,default=0)
    wallet=db.Column("wallet",db.Integer,default=0)
class Session(db.Model):
    __tablename__="session"
    id=db.Column(db.Integer, primary_key=True)
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
app.run(debug=True)