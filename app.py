from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secret key for session management (make sure to change it in production)
app.config['SECRET_KEY'] = 'your_secret_key'

# Database configuration (using SQLite here, you can change it for PostgreSQL or MySQL)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Create a User model (table) in the database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Route for the home page (landing page)
@app.route('/')
def home():
    return render_template('index.html')

# Route for Sign Up page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check if username or email already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists, please choose another one.', 'danger')
            return redirect(url_for('signup'))

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already registered, please use a different one.', 'danger')
            return redirect(url_for('signup'))

        # Hash the password before storing it in the database
        hashed_password = generate_password_hash(password, method='sha256')

        # Create a new user and add to the database
        new_user = User(full_name=full_name, username=username, password=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()

        flash('Sign up successful! Please log in.', 'success')
        return redirect(url_for('signin'))  # Redirect to the login page after successful sign up

    return render_template('signup.html')

# Route for Sign In page
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):  # Check if the password matches
            flash('Login successful!', 'success')
            return redirect(url_for('home'))  # Redirect to the home page after successful login
        else:
            flash('Login failed! Please check your username and/or password.', 'danger')

    return render_template('signin.html')

if __name__ == '__main__':
    # Create the database if it doesn't exist
    with app.app_context():
        db.create_all()

    app.run(debug=True)
