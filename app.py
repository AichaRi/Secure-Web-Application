from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import bleach
# Noufs part 
import hashlib  # For insecure password hashing (MD5)
import sqlite3  # For raw SQL queries (vulnerable to injection)
#end of the imports from noufs part

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

# Add this at the top of your app.py file (right after imports)

# Force database recreation on startup
with app.app_context():
    print("Dropping all tables...")
    db.drop_all()
    print("Creating all tables...")
    db.create_all()
    print("Database schema created successfully")

    # Ensure admin user exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        print("Creating admin user...")
        admin_password = bcrypt.generate_password_hash('adminpassword')
        admin_user = User(username='admin', password=admin_password, role='admin')
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully")

# securing cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,
    REMEMBER_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Optionally, add a relationship to user for easier querying
    user = db.relationship('User', backref='comments')


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                print(f"Logged in user: {user.username} (role: {user.role})")
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        comment_text = request.form.get('comment')  # Get the comment text
        if comment_text:
            # Sanitize the comment text to remove harmful HTML/JS
            sanitized_comment = bleach.clean(comment_text)
            new_comment = Comment(text=sanitized_comment, user_id=current_user.id)
            db.session.add(new_comment)
            db.session.commit()

    # Fetch all comments from the database
    comments = Comment.query.all()

    return render_template('dashboard.html', comments=comments)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        role = 'admin' if form.username.data == 'admin' else 'user'
        new_user = User(username=form.username.data, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# Noufs part 

# Vulnerable login (SQL Injection)
@app.route('/login_vulnerable', methods=['GET', 'POST'])
def login_vulnerable():
    # Debug message to terminal
    print("\n----- Login Vulnerable Route Accessed -----")
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        print(f"Login attempt with: Username={username}, Password={password}")
        
        # Hash the password using MD5 (insecure)
        md5_password = hashlib.md5(password.encode()).hexdigest()
        print(f"MD5 Hash: {md5_password}")
        
        # VULNERABLE to SQL Injection! 
        conn = sqlite3.connect('instance/database.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM user WHERE username = '{username}' AND password = '{md5_password}'"
        print(f"SQL Query: {query}")
        
        try:
            # Execute vulnerable query
            result = cursor.execute(query).fetchone()
            print(f"Query Result: {result}")
            conn.close()
            
            if result:
                print(f"User found in database with ID: {result[0]}")
                user = User.query.get(result[0])  # Get user by ID
                print(f"User object: {user}")
                
                if user:
                    print(f"Attempting to log in user: {user.username}")
                    login_user(user)
                    print("User logged in successfully, redirecting to dashboard")
                    return redirect(url_for('dashboard'))
                else:
                    print("ERROR: Could not find user object in SQLAlchemy database")
            else:
                print("No matching user found in database")
        except Exception as e:
            print(f"Exception occurred: {str(e)}")
            conn.close()
    
    # For GET requests or failed login
    return render_template('login_vulnerable.html', 
                          title="Vulnerable Login", 
                          form_action="/login_vulnerable")


@app.route('/register_vulnerable', methods=['GET', 'POST'])
def register_vulnerable():
    print("\n----- Register Vulnerable Route Accessed -----")
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        print(f"Registration attempt: Username={username}, Password={password}")
        
        # Check if username exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"Username '{username}' already exists")
            return render_template('register_vulnerable.html', 
                                  title="Vulnerable Registration", 
                                  form_action="/register_vulnerable")
        
        # Hash password with MD5 (INSECURE!)
        md5_password = hashlib.md5(password.encode()).hexdigest()
        print(f"MD5 Hash: {md5_password}")
        
        try:
            new_user = User(username=username, password=md5_password, role='user')  # Add role parameter
            db.session.add(new_user)
            db.session.commit()
            print(f"User '{username}' registered successfully")
            return redirect(url_for('login_vulnerable'))
        except Exception as e:
            print(f"Exception during registration: {str(e)}")
            db.session.rollback()
    
    # For GET requests
    return render_template('register_vulnerable.html', 
                          title="Vulnerable Registration", 
                          form_action="/register_vulnerable")


# Add this debug route
@app.route('/debug_db')
def debug_db():
    # Get all users
    users = User.query.all()
    result = '<h1>Database Debug</h1><ul>'
    
    for user in users:
        result += f'<li>ID: {user.id}, Username: {user.username}, Password: {user.password[:10]}..., Role: {user.role}</li>'
    
    result += '</ul>'
    return result


# Secure Admin Page (role-based via username demo)
# ======== Asia Part: Access Control Demo ========
@app.route('/admin_secure')
@login_required
def admin_secure():
    if current_user.role != 'admin':
        flash('Access denied: Admins only.')
        return redirect(url_for('dashboard'))
    return render_template('admin_secure.html')


# Insecure Admin Page (no access control)
# ======== Asia Part: Vulnerable Route Example ========
@app.route('/admin_insecure')
@login_required
def admin_insecure():
    return render_template('admin_insecure.html')


#Aicha Unsafe Comments section
@app.route('/comment_vulnerable', methods=['GET', 'POST'])
@login_required
def comment_vulnerable():
    if request.method == 'POST':
        comment_text = request.form.get('comment')  # Get the comment text
        if comment_text:
            # Do NOT sanitize the comment text – for XSS demo
            new_comment = Comment(text=comment_text, user_id=current_user.id)
            db.session.add(new_comment)
            db.session.commit()

    # Fetch all comments from the database
    comments = Comment.query.all()

    return render_template('comment_vulnerable.html', comments=comments)


# Initialize database when running the application directly
if __name__ == "__main__":
    with app.app_context():
        # This will recreate all tables from scratch
        db.drop_all()
        db.create_all()
        
        # Optionally, create an admin user for testing
        admin_exists = User.query.filter_by(username='admin').first()
        if not admin_exists:
            admin_password = bcrypt.generate_password_hash('adminpassword')
            admin_user = User(username='admin', password=admin_password, role='admin')
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully")
    
    # Run the app
    app.run(
        debug=True,
        port=5000,  # Changed to match the port in your error log
    )