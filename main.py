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
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://sql6484787:w55IcmUunw@sql6.freesqldatabase.com/sql6484787"
db = SQLAlchemy(app)

FERNET_KEY = "_2S4Rdhycz25AfVaQHRMiFTrpIdsG66h_2FPyvyLM2k="

from model import *
from controlller import *

app.run(threaded=True, debug=True, port=5003)