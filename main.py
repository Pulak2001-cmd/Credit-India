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

from model import *
from controlller import *

app.run(debug=True)