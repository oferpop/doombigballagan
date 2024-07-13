from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
from werkzeug.utils import secure_filename
from functools import wraps

# Configure Flask app
app = Flask(__name__, static_url_path='/static',
            static_folder='/Users/oferkorichoner/Desktop/jhon brise/new cours/doom_librarry/static/img')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(
    '/Users/oferkorichoner/Desktop/jhon brise/new cours/doom_librarry/static', 'img')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Change this to a more secure key
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

db = SQLAlchemy(app)
CORS(app)  # Enable CORS for all routes
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Customer model (merged with User)
class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    mail = db.Column(db.String(120), unique=True, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'city': self.city,
            'age': self.age,
            'mail': self.mail,
            'gender': self.gender,
            'role': self.role,
            'is_active': self.is_active
        }

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        db.session.commit()

# Loan model
class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cust_id = db.Column(db.Integer, db.ForeignKey(
        'customer.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    loan_date = db.Column(db.DateTime, nullable=False)
    return_date = db.Column(db.DateTime, nullable=False)
    customer = db.relationship(
        'Customer', backref=db.backref('loans', lazy=True))
    book = db.relationship(
        'Book', backref=db.backref('loan_records', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'cust_id': self.cust_id,
            'book_id': self.book_id,
            'loan_date': self.loan_date.strftime('%Y-%m-%d'),
            'return_date': self.return_date.strftime('%Y-%m-%d'),
            'book': {
                'id': self.book.id,
                'name': self.book.name
            } if self.book else None,
            'customer': {
                'id': self.customer.id,
                'name': self.customer.name,
                'mail': self.customer.mail
            } if self.customer else None
        }

# Book model
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    year_published = db.Column(db.Integer, nullable=False)
    type = db.Column(db.Integer, nullable=False)
    img = db.Column(db.String(200), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'author': self.author,
            'year_published': self.year_published,
            'type': self.type,
            'img': self.img
        }

# Function to check admin role
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        if current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper

# Routes
@app.route('/', methods=['GET'])
def welcome():
    return jsonify({'message': 'Welcome to the Library'})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('mail') or not data.get('password') or not data.get('username'):
        return jsonify({'error': 'Invalid input'}), 400

    if Customer.query.filter_by(mail=data['mail']).first():
        return jsonify({'error': 'Email is already taken'}), 400

    hashed_password = bcrypt.generate_password_hash(
        data['password']).decode('utf-8')
    new_customer = Customer(
        name=data['username'],
        city=data.get('city', ''),
        age=data.get('age', 0),
        mail=data['mail'],
        gender=data.get('gender', ''),
        password=hashed_password)
    db.session.add(new_customer)
    db.session.commit()

    # Automatically log in the user after registration
    access_token = create_access_token(
        identity={'mail': new_customer.mail, 'role': new_customer.role})
    return jsonify({'message': 'User registered successfully', 'access_token': access_token}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('mail') or not data.get('password'):
        return jsonify({'error': 'Invalid input'}), 400

    customer = Customer.query.filter_by(mail=data['mail']).first()
    if customer and bcrypt.check_password_hash(customer.password, data['password']):
        remember_me = data.get('remember_me', False)
        expires = timedelta(days=30) if remember_me else timedelta(hours=1)
        access_token = create_access_token(
            identity={'mail': customer.mail, 'role': customer.role}, expires_delta=expires)
        user_name = customer.mail
        if customer.role == 'admin':
            message = 'Welcome my master'
        else:
            message = f'Welcome {customer.mail}'
        return jsonify(message=message, access_token=access_token, user_name=user_name), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/admin', methods=['GET'])
@admin_required
def admin():
    return jsonify({'message': 'Welcome, Admin!'}), 200

# Protect a route with jwt_required
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    return jsonify(logged_in_as=current_user), 200

@app.route('/add_book', methods=['POST'])
@jwt_required()
def add_book():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':  # Only admin can add books
        return jsonify({'error': 'Admin access required'}), 403

    data = request.form
    if 'img' not in request.files:
        return jsonify({"error": "No image file provided"}), 400

    img = request.files['img']
    if img and allowed_file(img.filename):
        filename = secure_filename(img.filename)
        img.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        img_url = url_for('static', filename='img/' + filename)
    else:
        return jsonify({"error": "Invalid image format"}), 400

    new_book = Book(
        name=data['name'],
        author=data['author'],
        year_published=data['year_published'],
        type=data['type'],
        img=img_url
    )
    db.session.add(new_book)
    db.session.commit()
    return jsonify({'message': 'Book added!'}), 201

@app.route('/books/<int:book_id>', methods=['GET'])
def get_book_by_id(book_id):
    book = Book.query.get_or_404(book_id)
    loan = Loan.query.filter_by(book_id=book.id, return_date=None).first()
    book_dict = {
        'id': book.id,
        'name': book.name,
        'author': book.author,
        'year_published': book.year_published,
        'type': book.type,
        'img': book.img,
        'is_on_loan': loan is not None,
        'loan_details': {
            'loan_id': loan.id,
            'loan_date': loan.loan_date,
            'due_date': loan.return_date,
            'customer_name': loan.customer.name
        } if loan else None
    }
    return jsonify(book_dict)

@app.route('/books', methods=['GET'])
def get_books():
    book_name = request.args.get('name')
    if book_name:
        books = Book.query.filter(Book.name.like(f"%{book_name}%")).all()
    else:
        books = Book.query.all()

    result = []
    for book in books:
        loan = Loan.query.filter_by(book_id=book.id, return_date=None).first()
        book_dict = {
            'id': book.id,
            'name': book.name,
            'author': book.author,
            'year_published': book.year_published,
            'type': book.type,
            'img': book.img,
            'is_on_loan': loan is not None,
            'loan_details': {
                'loan_id': loan.id,
                'loan_date': loan.loan_date,
                'due_date': loan.return_date,
                'customer_name': loan.customer.name
            } if loan else None
        }
        result.append(book_dict)

    return jsonify(result)

@app.route('/books/<int:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':  # Only admin can update books
        return jsonify({'error': 'Admin access required'}), 403

    book = Book.query.get_or_404(book_id)
    data = request.get_json()
    for key, value in data.items():
        setattr(book, key, value)
    db.session.commit()
    return jsonify(book.to_dict())

@app.route('/books/<int:book_id>', methods=['DELETE'])
@jwt_required()
def delete_book(book_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':  # Only admin can delete books
        return jsonify({'error': 'Admin access required'}), 403

    book = Book.query.get_or_404(book_id)
    Loan.query.filter_by(book_id=book_id).delete()
    db.session.delete(book)
    db.session.commit()
    return '', 204

@app.route('/add_customer', methods=['POST'])
def add_customer():
    data = request.json
    new_customer = Customer(
        name=data['name'],
        city=data['city'],
        age=data['age'],
        mail=data['mail'],
        gender=data['gender'],
        password=data['password'],  # Ensure you hash the password appropriately
        is_active=True
    )
    db.session.add(new_customer)
    db.session.commit()
    return jsonify({'message': 'Customer added successfully!'}), 201

@app.route('/customers', methods=['GET'])
@jwt_required()
def get_customers():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    customers = Customer.query.all()
    return jsonify([customer.to_dict() for customer in customers])

@app.route('/customers/<int:customer_id>', methods=['GET'])
def get_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    return jsonify(customer.to_dict())

@app.route('/update_customer/<int:customer_id>', methods=['POST'])
def update_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    data = request.json
    customer.update(**data)
    return jsonify({'message': 'Customer updated successfully', 'customer': customer.to_dict()}), 200

@app.route('/customers/<int:customer_id>', methods=['DELETE'])
def delete_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    customer.is_active = False
    db.session.commit()
    return jsonify({'message': 'Customer marked as inactive'}), 200

@app.route('/loans', methods=['GET'])
@jwt_required()
def get_loans():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    book_id = request.args.get('book_id')
    book_name = request.args.get('book_name')
    customer_id = request.args.get('customer_id')
    customer_email = request.args.get('customer_email')

    query = Loan.query.join(Customer).join(Book)

    if book_id:
        query = query.filter(Book.id == book_id)
    if book_name:
        query = query.filter(Book.name.ilike(f"%{book_name}%"))
    if customer_id:
        query = query.filter(Customer.id == customer_id)
    if customer_email:
        query = query.filter(Customer.mail.ilike(f"%{customer_email}%"))

    loans = query.all()

    formatted_loans = []
    for loan in loans:
        loan_dict = loan.to_dict()
        formatted_loan = {
            'customer_id': loan_dict['customer']['id'] if loan_dict['customer'] else None,
            'customer_name': loan_dict['customer']['name'] if loan_dict['customer'] else 'Unknown',
            'customer_email': loan_dict['customer']['mail'] if loan_dict['customer'] else 'Unknown',
            'book_name': loan_dict['book']['name'] if loan_dict['book'] else 'Unknown',
            'book_id': loan_dict['book']['id'] if loan_dict['book'] else None,
            'loan_date': loan_dict['loan_date'],
            'return_date': loan_dict['return_date']
        }
        formatted_loans.append(formatted_loan)
    return jsonify(formatted_loans)

@app.route('/loans/<email>', methods=['GET'])
def get_loans_by_email(email):
    customer = Customer.query.filter_by(mail=email).first()
    if not customer:
        return jsonify({'error': 'Customer not found'}), 404

    loans = Loan.query.filter_by(cust_id=customer.id).all()
    formatted_loans = []
    for loan in loans:
        loan_dict = loan.to_dict()
        formatted_loan = {
            'customer_id': loan_dict['customer']['id'],
            'customer_name': loan_dict['customer']['name'],
            'customer_email': loan_dict['customer']['mail'],
            'book_name': loan_dict['book']['name'],
            'book_id': loan_dict['book']['id'],
            'loan_date': loan_dict['loan_date'],
            'return_date': loan_dict['return_date']
        }
        formatted_loans.append(formatted_loan)
    return jsonify(formatted_loans)

@app.route('/my_loans', methods=['GET'])
@jwt_required()
def get_my_loans():
    current_user = get_jwt_identity()
    customer = Customer.query.filter_by(mail=current_user['mail']).first()

    if not customer:
        return jsonify({'error': 'Customer not found'}), 404

    loans = Loan.query.filter_by(cust_id=customer.id).all()
    formatted_loans = []
    for loan in loans:
        loan_dict = loan.to_dict()
        formatted_loan = {
            'book_name': loan_dict['book']['name'] if loan_dict['book'] else 'Unknown',
            'book_id': loan_dict['book']['id'] if loan_dict['book'] else None,
            'loan_date': loan_dict['loan_date'],
            'return_date': loan_dict['return_date']
        }
        formatted_loans.append(formatted_loan)
    return jsonify(formatted_loans)

@app.route('/add_loan', methods=['POST'])
@jwt_required()
def add_loan():
    current_user_identity = get_jwt_identity()
    customer = Customer.query.filter_by(
        mail=current_user_identity['mail']).first()

    if not customer:
        return jsonify({'error': 'Customer not found'}), 404

    data = request.get_json()
    if current_user_identity['role'] == 'admin':
        # Admin can specify any customer ID
        customer_id = data.get('cust_id')
        if not customer_id:
            return jsonify({'error': 'Customer ID is required for admin'}), 400
    else:
        # For non-admin users, use their own customer ID
        customer_id = customer.id
    book_id = data['book_id']
    ongoing_loan = Loan.query.filter_by(book_id=book_id).filter(
        Loan.return_date >= datetime.now()).first()
    if ongoing_loan:
        return jsonify({'error': 'Book is currently on loan'}), 400

    book = Book.query.get(book_id)
    if book.type == 1:
        max_loan_days = 10
    elif book.type == 2:
        max_loan_days = 5
    elif book.type == 3:
        max_loan_days = 2
    else:
        return jsonify({'error': 'Invalid book type'}), 400

    loan_date = datetime.now()
    return_date = loan_date + timedelta(days=max_loan_days)

    new_loan = Loan(
        cust_id=customer_id,
        book_id=book_id,
        loan_date=loan_date,
        return_date=return_date
    )
    db.session.add(new_loan)
    db.session.commit()
    return jsonify(new_loan.to_dict()), 201

@app.route('/loans/<int:book_id>/return', methods=['PUT'])
@jwt_required()
def return_loan(book_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':  # Only admin can return loans
        return jsonify({'error': 'Admin access required'}), 403

    loan = Loan.query.filter_by(book_id=book_id).first()
    if not loan:
        return jsonify({'error': 'Loan not found'}), 404
    db.session.delete(loan)
    db.session.commit()
    return jsonify({'message': 'Book returned successfully'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Add initial admin user if it doesn't exist
        if not Customer.query.filter_by(mail='oferpop@gmail.com').first():
            hashed_password = bcrypt.generate_password_hash(
                'ok1505').decode('utf-8')
            initial_admin = Customer(name='oferpop', mail='oferpop@gmail.com',
                                     city='', age=0, gender='', password=hashed_password, role='admin')
            db.session.add(initial_admin)
            db.session.commit()
    app.run(debug=True)
