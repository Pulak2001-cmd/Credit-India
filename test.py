from datetime import datetime


class AllProducts(db.Model):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    price = db.Column(db.Float(precision=2))
    description=db.column(db.String(80))
    qty=user_id = db.Column(db.Integer)
    image = db.Column(db.String(80))
    product_type = db.Column(db.String(80))
    is_added = db.column(db.Boolean,default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User')

    @classmethod
    def find_by_name(cls, name):
        return cls.query.filter_by(name=name).first()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()


    '''def __init__(self, name, price, description, is_added, user_id, qty):
        self.name = name
        self.price = price
        self.description = description
        self.qty = qty
        self.user_id = user_id
        self.is_added = is_added'''


class Cart(db.Model):
    __tablename__ = 'cart'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    price = db.Column(db.Float(precision=2))
    description=db.column(db.String(80))
    product_type = db.Column(db.String(80))
    qty = db.Column(db.Integer)
    image = db.Column(db.String(80))
    is_added = db.column(db.Boolean,default=1)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    product = db.relationship('AllProducts')


class Order(db.Model):
    __tablename__ = 'order'
    id = db.Column(db.Integer,  primary_key=True)


class Bill(db.Model):
    __tablename__ = 'billgenerate'

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.String(80))
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    description=db.column(db.String(80))
    total_price = db.Column(db.Integer)
    date_time = db.Column(db.DateTime)
    #is_added = db.column(db.Boolean,default=1)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    cart = db.relationship('Cart')



class AddAllProducts(Resource):
    @authenticate_api
    def post(self,**kwargs):
        User = kwargs["user"]
        data=request.get_json()
        id=data["id"]
        name=data["name"]
        price=data["price"]
        product_type=data["product_type"]
        user_id=User.id
        description=data["description"]
        qty=data["qty"]
        image=data["image"]
        get_user = AllProducts.query.filter(and_(AllProducts.name==name,AllProducts.qty==qty,user_id==AllProducts.user_id)).first()
        if get_user is not None:
            return errorMessage("Product already exists")
        entry=AllProducts(name=name,price=price,description=description, is_added=0, product_type=product_type, user_id=User.id, qty=qty,image=image)
        db.session.add(entry)
        db.session.commit()
        result = {
            "error": "",
            "status": True
        }
        return jsonify(result) 


class DisplayAllProducts(Resource):
    @authenticate_api
    def get(self,**kwargs):
        User = kwargs["user"]
        get_allproducts=AllProducts.query.filter((User.id==AllProducts.user_id)).all()
        result=[]
        for product in get_allproducts:
            result.append ({
            "name": product.name,
            "price": product.price,
            "description": product.description,
            "type": product.product_type,
            "qty": product.qty,
            "image": product.image
        })
        return jsonify(result)
            
    
class DisplayCart(Resource):
    @authenticate_api
    def get(self,**kwargs):
        User = kwargs["user"]
        get_allproducts=Cart.query.filter(and_(User.id==Cart.user_id)).all()
        result=[]
        for product in get_allproducts:
            result.append ({
            "name": product.name,
            "price": product.price,
            "description": product.description,
            "type": product.product_type
            "qty": product.qty,
             "image": product.image
        })
        return jsonify(result)


class AddtoCart(Resource):
    @authenticate_api
    def post(self,**kwargs):
        User = kwargs["user"]
        data=request.get_json()
        get_product=AllProducts.query.filter(and_(User.id==AllProducts.user_id,AllProducts.name==data["name"])).first()
        if get_product.qty == 0:
            return errorMessage("Product doesnt exist")
        name=get_product.name
        price=get_product.price
        description=get_product.description
        product_type=get_product.product_type
        qty=1
        image=get_product.image
        is_added=1
        user_id=User.is_added
        get_presence=Cart.query.filter(and_(User.id==Cart.user_id,Cart.name==name)).first()
        if get_presence is not None:
            get_presence.qty=get_presence.qty+1
            db.session.commit()
        
        entry=Cart(name=name,price=price,description=description, is_added=1, product_type=product_type, user_id=User.id, qty=qty,image=image)
        db.session.add(entry)
        db.session.commit()
        result = {
            "error": "",
            "status": True
        }
        return jsonify(result)

class RemovefromCart(Resource):
    @authenticate_api
    def post(self,**kwargs):
        User = kwargs["user"]
        data=request.get_json()
        db.session.Cart.query.filter(and_(User.id==Cart.user_id,Cart.name==data["name"])).delete()
        db.session.commit()

class RemoveAllfromCart(Resource):
    @authenticate_api
    def post(self,**kwargs):
        User = kwargs["user"]
        data=request.get_json()
        db.session.Cart.query.filter((User.id==Cart.user_id)).delete()
        db.session.commit()
        


class CustomerCred(Resource):
    @authenticate_api
    def post(self,**kwargs):
        User = kwargs["user"]
        data=request.get_json()
        customer_id=data["customer_id"]
        description=data["description"]
        date_time=datetime.now()
        order_id=1
        user_id=User.id
        get_allproducts=Cart.query.filter(and_(User.id==Cart.user_id)).all()
        #res=0
        for product in get_allproducts:
            res+=product.price*product.qty
        total_price=res
        new_order=Order()
        order_id=new_order.id
        entry=Bill(customer_id=customer_id,order_id=order_id, description=description, order_id=order_id, product_type=product_type, date_time=date_time, total_price=total_price, user_id=User.id)
        db.session.add(entry)
        db.session.commit()
        result = {
            "customer_id": customer_id,
            "order_id": order_id,
            "description": description,
            "type": product_type,
            "total_price": total_price,
            "date_time": date_time
        }
        return jsonify(result) 

class DisplayBills(Resource):
    @authenticate_api
    def get(self,**kwargs):
        User = kwargs["user"]
        get_bills=Bill.query.filter(and_(User.id==Bill.user_id)).all()
        result=[]
        for bill in get_bills:
            result.append ({
            "customer_id": bill.customer_id,
            "order_id": bill.order_id,
            "description": bill.description,
            "total_price": bill.total_price,
            "date_time": product.date_time
        })
        return jsonify(result)

class DisplaybyCustomers(Resource):
    @authenticate_api
    def post(self,**kwargs):
        User = kwargs["user"]
        data=request.get_json()
        get_bills=Bill.query.filter(and_(User.id==Bill.user_id, Bill.customer_id==data["customer_id"] )).all()
        result=[]
        for bill in get_bills:
            result.append ({
            "customer_id": bill.customer_id,
            "order_id": bill.order_id,
            "description": bill.description,
            "total_price": bill.total_price,
            "date_time": product.date_time
        })
        return jsonify(result)
    
class OrderbyDate(Resource):
    @authenticate_api
    def post(self,**kwargs):
        User = kwargs["user"]
        data=request.get_json()
        get_bills=Bill.query.filter(and_(User.id==Bill.user_id, Bill.date_time==data["date_time"] )).all()
        result=[]
        for bill in get_bills:
            result.append ({
            "customer_id": bill.customer_id,
            "order_id": bill.order_id,
            "description": bill.description,
            "total_price": bill.total_price,
            "date_time": product.date_time
        })
        return jsonify(result)

class OrderbyDateRange(Resource):
    @authenticate_api
    def post(self,**kwargs):
        User = kwargs["user"]
        data=request.get_json()
        days=data["date_range"]
        dt1=datetime.date.today() - datetime.timedelta(days=days)
        get_bills=Bill.query.filter(and_(User.id==Bill.user_id, Bill.date_time>=dt1 )).all()
        result=[]
        for bill in get_bills:
            result.append ({
            "customer_id": bill.customer_id,
            "order_id": bill.order_id,
            "description": bill.description,
            "total_price": bill.total_price,
            "date_time": product.date_time
        })
        return jsonify(result)

class DisplayCustomers(Resource):
    @authenticate_api
    def get(self,**kwargs):
        User = kwargs["user"]  
        get_bills=Bill.query.filter(and_(User.id==Bill.user_id)).all()
        customers=[]
        for bill in get_bills:
            if customers.count(bill.customer_id)==0:
                customers.append(bill.customer_id)
        return jsonify(customers)