#app.py

from datetime import datetime, timedelta
from fileinput import filename
import json,time,os
from functools import wraps
from flask import Flask, jsonify, render_template, request, send_from_directory, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
# from sqlalchemy.orm import class_mapper
import jwt
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from sqlalchemy import ForeignKey
from werkzeug.utils import secure_filename
import traceback


app = Flask(__name__)
app.secret_key = 'secret_secret_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Set the expiration time for access tokens
CORS(app)  # Enable CORS for all routes


#* SQLAlchemy configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///samp.sqlite3'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:1234@localhost/restaurant'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# Get the directory where app.py is located
app_directory = os.path.dirname(__file__)

# Define the directory where you want to store the uploaded files
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


class Customer(db.Model):
    cust_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    cus_name = db.Column(db.String(100))
    city = db.Column(db.String(100))
    age = db.Column(db.Integer)
    email = db.Column(db.String(100))
    role = db.Column(db.String(100), nullable=False)
    img = db.Column(db.String(255))  # Define img attribute to store the filename of the image



class Book(db.Model):
    book_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    book_name = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    year_published = db.Column(db.Integer)
    loan_type = db.Column(db.Integer, nullable=False)  # Change to Integer for loan_type
    borrowed = db.Column(db.Boolean, default=False)  #is the book borrowd or not
    userid = db.Column(db.Integer, db.ForeignKey('customer.cust_id', ondelete='CASCADE'), nullable=False) #when a referenced record in the Customer table is deleted, the corresponding records in the Book table will also be deleted.
    user = db.relationship('Customer', backref=db.backref('books', lazy=True))


class Loans(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cust_id = db.Column(db.Integer, ForeignKey('customer.cust_id'), nullable=False)
    customer = db.relationship('Customer', backref=db.backref('loans', lazy=True))
    book_id = db.Column(db.Integer, ForeignKey('book.book_id'), nullable=False)
    book = db.relationship('Book', backref=db.backref('loans', lazy=True))
    loan_date = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    return_date = db.Column(db.DateTime)


class LateLoans(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, ForeignKey('loans.id'), unique=True, nullable=False)
    loan = db.relationship('Loans', backref=db.backref('late_loan', uselist=False, lazy=True))
    cust_id = db.Column(db.Integer, ForeignKey('customer.cust_id'), nullable=False)
    book_id = db.Column(db.Integer, ForeignKey('book.book_id'), nullable=False)
    loan_date = db.Column(db.DateTime, nullable=False)
    return_date = db.Column(db.DateTime, nullable=False)
    actual_return_date = db.Column(db.DateTime, nullable=False)

    def __init__(self, loan_id, cust_id, book_id, loan_date, return_date, actual_return_date):
        self.loan_id = loan_id
        self.cust_id = cust_id
        self.book_id = book_id
        self.loan_date = loan_date
        self.return_date = return_date
        self.actual_return_date = actual_return_date

    def __repr__(self):
        return '<Customer %r>' % self.username


def calculate_return_date(self):
        # Use loan_type information from Book class
        if self.book.loan_type == 1:
            return self.loan_date + timedelta(days=10)
        elif self.book.loan_type == 2:
            return self.loan_date + timedelta(days=5)
        elif self.book.loan_type == 3:
            return self.loan_date + timedelta(days=2)
        else:
            # Handle invalid loan types
            raise ValueError("Invalid loan type")


# Generate a JWT
def generate_token(user_id):
    expiration = int(time.time()) + 3600  # Set the expiration time to 1 hour from the current time
    payload = {'user_id': user_id, 'exp': expiration}
    token = jwt.encode(payload, 'secret-secret-key', algorithm='HS256')
    return token


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401


        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401


        return f(current_user_id, *args, **kwargs)


    return decorated


def model_to_dict(model):
    serialized_model = {}
    for key in model.__mapper__.c.keys():
        serialized_model[key] = getattr(model, key)
    return serialized_model


# opening cors to everyone for tests
CORS(app)


@app.route('/register', methods=['POST'])
def register():
    try:
        # Get JSON data from request
        data = request.get_json()

        # Extract data from JSON
        username = data.get('username')
        password = data.get('password')
        cus_name = data.get('cus_name')
        city = data.get('city')
        age = data.get('age')
        email = data.get('email')
        role = data.get('role')
        print(username, password, cus_name, city, age, email, role)

        # Perform input validation (check for required fields, etc.)
        if not (username and password and cus_name and city and age and email and role):
            return jsonify({'message': 'All fields are required'}), 400

        # Check if the username is already taken
        existing_user = Customer.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'message': 'Username is already taken'}), 400

        # Hash and salt the password using Bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Save the file to the server
        file = request.files.get('file')
        filename = None
        if file:
            print("Uploaded file:", file.filename)
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            print("Uploaded file saved:", filepath)

        # Create a new Customer and add to the database
        new_cust = Customer(username=username, password=hashed_password, role=role, cus_name=cus_name,
                            city=city, age=age, email=email, img=filename)
        db.session.add(new_cust)
        db.session.commit()

        return jsonify({'message': 'User registered successfully', 'cust_id': new_cust.cust_id}), 201

    except Exception as e:
        import traceback
        traceback.print_exc()  # Print the exception traceback to the console
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500



@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Retrieve the user from the database based on the provided username
    customer = Customer.query.filter_by(username=username).first()

    # If a user with the provided username exists and the password matches, generate an access token
    if customer and bcrypt.check_password_hash(customer.password, password.encode('utf-8')):
        # Generate an access token
        access_token = create_access_token(identity=customer.cust_id)

        # Get the user's role
        user_role = customer.role

        # Print a message indicating that the authorization token was created successfully
        print('Authorization token created successfully for user:', customer.username)

        # Return a success message along with the access token and user's role
        response = jsonify({'message': 'Login successful', 'access_token': access_token, 'role': user_role})
        response.headers['Content-Type'] = 'application/json; charset=utf-8'  # Set charset
        return response, 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401



@app.route('/addbooks', methods=['POST'])
@jwt_required()
def add_books():
    try:
        # Get the current user's role
        current_user_id = get_jwt_identity()
        current_user = Customer.query.get(current_user_id)

        # Check if the current user is a librarian (role '1')
        if current_user.role != '1':
            return jsonify({'message': 'You do not have permission to add books'}), 403

        # Get book details from the request data
        request_data = request.get_json()
        print("Request Data:", request_data)  # Add this line to print the request data
        if not request_data:
            return jsonify({'message': 'No data provided in the request'}), 400
        
        book_name = request_data.get('book_name')
        author = request_data.get('author')
        year_published = request_data.get('year_published')
        loan_type = request_data.get('loan_type')

        # Validate input data
        if not all([book_name, author, year_published, loan_type]):
            return jsonify({'message': 'Missing required fields'}), 400

        # Create a new book with the provided details
        new_book = Book(
            book_name=book_name,
            author=author,
            year_published=year_published,
            loan_type=loan_type,
            borrowed=False,  # Set borrowed attribute to False
            userid=current_user_id
        )

        # Add the new book to the database
        db.session.add(new_book)
        db.session.commit()

        # Return a success message
        return jsonify({'message': 'Book added successfully'}), 201

    except Exception as e:
        traceback.print_exc()  # Add this line to print the traceback
        return jsonify({'error': str(e)}), 500





@app.route('/getbooks', methods=['GET'])
def get_books():
    try:
        # Query all books from the database
        all_books = Book.query.all()

        # Serialize the books to a list of dictionaries
        books_list = []
        for book in all_books:
            # Get the borrowed status
            borrowed_status = "Borrowed" if book.borrowed else "Available"

            # Serialize book to a dictionary
            book_dict = model_to_dict(book)
            book_dict['borrowed_status'] = borrowed_status
            books_list.append(book_dict)

        return jsonify({'books': books_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/deletebook/<int:book_id>', methods=['DELETE'])
@jwt_required()
def delete_book(book_id):
    try:
        # Get the current user's role
        current_user_id = get_jwt_identity()
        current_user = Customer.query.get(current_user_id)

        # Check if the current user is a librarian (role '1')
        print(current_user.role)
        if current_user.role != '1':
            return jsonify({'error': 'only librarians have permission to delete books'}), 403

        # Query the book to be deleted
        book_to_delete = Book.query.get(book_id)

        if not book_to_delete:
            return jsonify({'message': 'Book not found'}), 404

        # Delete the book from the database
        db.session.delete(book_to_delete)
        db.session.commit()

        return jsonify({'message': 'Book deleted successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/updatebook/<int:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
    try:
        # Get the current user's role
        current_user_id = get_jwt_identity()
        current_user = Customer.query.get(current_user_id)

        # Check if the current user is a librarian (role '1')
        if current_user.role != '1':
            return jsonify({'message': 'You do not have permission to update books'}), 403

        # Query the book to be updated
        book_to_update = Book.query.get(book_id)

        if not book_to_update:
            return jsonify({'message': 'Book not found'}), 404

        # Get form data from request
        book_name = request.form.get('book_name')
        author = request.form.get('author')
        year_published = request.form.get('year_published')
        loan_type = request.form.get('loan_type')
        borrowed = request.form.get('borrowed')

        # Update the book information
        book_to_update.book_name = book_name or book_to_update.book_name
        book_to_update.author = author or book_to_update.author
        book_to_update.year_published = year_published or book_to_update.year_published
        book_to_update.loan_type = loan_type or book_to_update.loan_type
        book_to_update.borrowed = borrowed or book_to_update.borrowed

        # Commit the changes to the database
        db.session.commit()

        return jsonify({'message': 'Book updated successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/lendbook', methods=['POST'])
@jwt_required()
def lend_book():
    try:
        # Get the current user's role and ID
        current_user_id = get_jwt_identity()
        current_user = Customer.query.get(current_user_id)

        # Check if the current user is a customer (role '0')
        if current_user.role != '0':
            return jsonify({'message': 'Only customers can borrow books'}), 403

        # Get form data from request
        book_id = request.form.get('book_id')

        # Query the book to be borrowed
        book_to_borrow = Book.query.get(book_id)

        if not book_to_borrow:
            return jsonify({'message': 'Book not found'}), 404

        # Check if the book is already borrowed
        if book_to_borrow.borrowed:
            return jsonify({'message': 'Book is already borrowed'}), 400

        # Update the borrowed flag to indicate the book is borrowed
        book_to_borrow.borrowed = True

        # Set the loan date to the current date
        book_to_borrow.loan_date = datetime.now()

        # Calculate the return date based on loan type
        return_date = book_to_borrow.calculate_return_date()

        # Commit the changes to the database
        db.session.commit()

        # Print a message to the terminal
        print('Book borrowed successfully. Return date:', return_date.strftime('%Y-%m-%d'))

        # Provide a response with the return date
        return jsonify({'message': 'Book borrowed successfully', 'return_date': return_date.strftime('%Y-%m-%d')}), 200

    except Exception as e:
        # Print an error message to the terminal
        print('Error during book borrowing:', str(e))
        return jsonify({'error': str(e)}), 500




@app.route('/returnbook/<int:lend_id>', methods=['POST'])
@jwt_required()
def return_book(lend_id):
    try:
        # Get the current user's role and ID
        current_user_id = get_jwt_identity()
        current_user = Customer.query.get(current_user_id)

        # Check if the current user is a customer (role '0')
        if current_user.role != '0':
            return jsonify({'message': 'You do not have permission to return books'}), 403

        # Query the book to be returned
        returned_book = Loans.query.get(lend_id)

        if not returned_book:
            return jsonify({'message': 'Loan record not found'}), 404

        # Check if the book is already returned
        if not returned_book.book.borrowed:
            return jsonify({'message': 'Book is already returned'}), 400

        # Set the return date to the current date
        returned_book.return_date = datetime.now()

        # Calculate the difference between the return date and the expected return date
        late_days = (returned_book.return_date - returned_book.loan_date).days

        # Determine if the book was returned on time or late based on loan type
        if late_days <= 0:
            # Book returned on time
            returned_book.book.borrowed = False
            db.session.commit()
            print(f'Book returned successfully on time. Return date: {returned_book.return_date.strftime("%Y-%m-%d")}')
            return jsonify({'message': 'Book returned successfully on time'}), 200
        else:
            # Book returned late
            returned_book.book.borrowed = False
            late_loan = LateLoans(
                loan_id=returned_book.id,
                cust_id=returned_book.cust_id,
                book_id=returned_book.book_id,
                loan_date=returned_book.loan_date,
                return_date=returned_book.return_date,
                actual_return_date=returned_book.return_date
            )
            db.session.add(late_loan)
            db.session.commit()
            print(f'Book returned successfully, but {late_days} days late. Return date: {returned_book.return_date.strftime("%Y-%m-%d")}')
            return jsonify({'message': f'Book returned successfully, but {late_days} days late'}), 200

    except Exception as e:
        # Print an error message to the terminal
        print('Error during book returning:', str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/getusers', methods=['GET'])
@jwt_required()
def get_users():
    try:
        # Get the current user's role and ID
        current_user_id = get_jwt_identity()
        current_user = Customer.query.get(current_user_id)

        # Check if the current user is a librarian (role '1')
        if current_user.role != '1':
            return jsonify({'message': 'You do not have permission to view users'}), 403

        # Fetch all users from the database
        users = Customer.query.all()

        # Convert the user data to a list of dictionaries with borrowed books
        users_list = []
        for user in users:
            user_data = {
                'cust_id': user.cust_id,
                'username': user.username,
                'cus_name': user.cus_name,
                'city': user.city,
                'age': user.age,
                'email': user.email,
                'role': user.role,
                'borrowed_books': [{'book_id': book.book_id, 'book_name': book.book_name} for book in user.books if book.borrowed]
            }
            users_list.append(user_data)

        return jsonify({'users': users_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/deleteuser/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    try:
        # Get the current user's role and ID
        current_user_id = get_jwt_identity()

        # Debug print to check the current user's ID
        print("Current User ID:", current_user_id)

        # Check if the current user is a librarian (role '1')
        current_user_role = Customer.query.filter_by(cust_id=current_user_id).first().role

        # Debug print to check the current user's role
        print("Current User Role:", current_user_role)

        if current_user_role != '1':
            return jsonify({'message': 'You do not have permission to delete users'}), 403

        # Query the user to be deleted
        user_to_delete = Customer.query.get(user_id)

        if not user_to_delete:
            return jsonify({'message': 'User not found'}), 404

        # Check if the user has any borrowed books
        if user_to_delete.books:
            # Automatically return the borrowed books to the library
            for book in user_to_delete.books:
                if book.borrowed:
                    book.borrowed = False

                    # Add logic to save overdue data to LateLoans table if needed

            db.session.commit()

        # Delete the user
        db.session.delete(user_to_delete)
        db.session.commit()

        return jsonify({'message': 'User deleted successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)