from flask import Flask, request, jsonify, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import bcrypt
from authlib.integrations.flask_client import OAuth
import os
import secrets

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///databaseims.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Database Initialization
db = SQLAlchemy(app)

# Models
class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=False)

class User(db.Model):
    __tablename__ = 'users'
    phone = db.Column(db.String(20), primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'

class Product(db.Model):
    __tablename__ = 'products'
    ProductID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(100), nullable=False)
    Description = db.Column(db.String(200), nullable=True)
    Price = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f'<Product {self.Name}>'

class Order(db.Model):
    __tablename__ = 'orders'
    OrderID = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    total_price = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f'<Order {self.OrderID}>'

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    OrderItemID = db.Column(db.Integer, primary_key=True)
    OrderID = db.Column(db.Integer, db.ForeignKey('orders.OrderID'), nullable=False)
    ProductID = db.Column(db.Integer, db.ForeignKey('products.ProductID'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

    order = db.relationship('Order', backref=db.backref('order_items', lazy=True))
    product = db.relationship('Product', backref=db.backref('order_items', lazy=True))

    def __repr__(self):
        return f'<OrderItem {self.OrderItemID}>'

# Database Functions
def load_config_from_db():
    configs = Config.query.all()
    for config in configs:
        os.environ[config.key] = config.value

# OAuth Configuration
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    client_kwargs={'scope': 'openid profile email'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

@app.route('/login/google')
def login_google():
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    redirect_uri = url_for('authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, state=state)

@app.route('/authorize')
def authorize():
    try:
        state = request.args.get('state', None)
        stored_state = session.get('oauth_state', None)
        if state != stored_state:
            return jsonify({'error': 'Invalid state parameter'}), 400

        token = oauth.google.authorize_access_token()
        user_info = oauth.google.parse_id_token(token)
        email = user_info.get('email')

        user = User.query.filter_by(email=email).first()
        if user is None:
            return jsonify({'error': 'Unauthorized email'}), 401

        return jsonify({'message': 'Login successful'})

    except Exception as e:
        return jsonify({'error': 'OAuth error', 'message': str(e)}), 500

# API Endpoints
@app.route('/add_product', methods=['POST'])
def add_product():
    data = request.json
    product = Product(
        Name=data['Name'],
        Description=data.get('Description', ''),
        Price=data['Price']
    )
    db.session.add(product)
    db.session.commit()
    return jsonify({'message': 'Product added!'}), 201

@app.route('/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{
        'ProductID': product.ProductID,
        'Name': product.Name,
        'Description': product.Description,
        'Price': product.Price
    } for product in products])

@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{
        'phone': user.phone,
        'email': user.email
    } for user in users])

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    user = User(
        phone=data['phone'],
        email=data['email'],
        password_hash=hashed_password.decode('utf-8')
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created!'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({'message': 'Login successful!'})
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/add_order', methods=['POST'])
def add_order():
    data = request.json
    order = Order(
        email=data['email'],
        phone_number=data['phone_number'],
        address=data['address'],
        total_price=data['total_price']
    )
    db.session.add(order)
    db.session.commit()
    return jsonify({'message': 'Order added!'}), 201

@app.route('/orders', methods=['GET'])
def get_orders():
    orders = Order.query.all()
    return jsonify([{
        'OrderID': order.OrderID,
        'email': order.email,
        'phone_number': order.phone_number,
        'address': order.address,
        'total_price': order.total_price,
        'order_items': [{
            'OrderItemID': item.OrderItemID,
            'ProductID': item.ProductID,
            'quantity': item.quantity,
            'price': item.price
        } for item in order.order_items]
    } for order in orders])

@app.route('/add_order_item', methods=['POST'])
def add_order_item():
    data = request.json
    order_item = OrderItem(
        OrderID=data['OrderID'],
        ProductID=data['ProductID'],
        quantity=data['quantity'],
        price=data['price']
    )
    db.session.add(order_item)
    db.session.commit()
    return jsonify({'message': 'Order item added!'}), 201

@app.route('/order_items', methods=['GET'])
def get_order_items():
    order_items = OrderItem.query.all()
    return jsonify([{
        'OrderItemID': item.OrderItemID,
        'OrderID': item.OrderID,
        'ProductID': item.ProductID,
        'quantity': item.quantity,
        'price': item.price
    } for item in order_items])

# Main
if __name__ == '__main__':
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()
        load_config_from_db()

    app.run(debug=True)












