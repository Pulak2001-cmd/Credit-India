from main import db

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