from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production

# Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename, types=ALLOWED_EXTENSIONS):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in types

def init_db():
    """Initialize the database and create required tables"""
    conn = sqlite3.connect('jobportal.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        email TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        photo TEXT NOT NULL,
                        resume TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Companies table
    cursor.execute('''CREATE TABLE IF NOT EXISTS companies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        company_name TEXT NOT NULL UNIQUE,
                        email TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        logo TEXT NOT NULL,
                        policy_doc TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Job Listings table
    cursor.execute('''CREATE TABLE IF NOT EXISTS job_listings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        company_id INTEGER NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        requirements TEXT NOT NULL,
                        salary_range TEXT,
                        location TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (company_id) REFERENCES companies (id))''')
    
    # Applications table
    cursor.execute('''CREATE TABLE IF NOT EXISTS applications (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        job_id INTEGER NOT NULL,
                        user_id INTEGER NOT NULL,
                        status TEXT DEFAULT 'pending',
                        cover_letter TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (job_id) REFERENCES job_listings (id),
                        FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    conn.commit()
    conn.close()

init_db()

def get_db():
    """Helper function to get database connection"""
    conn = sqlite3.connect('jobportal.db')
    conn.row_factory = sqlite3.Row
    return conn

# User routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    elif 'company_id' in session:
        return redirect(url_for('company_dashboard'))
    return redirect(url_for('login_signup'))

@app.route('/login', methods=['GET', 'POST'])
def login_signup():
    if request.method == 'POST':
        if 'signup' in request.form:  # Handle User Signup
            username = request.form['username']
            email = request.form['email']
            password = generate_password_hash(request.form['password'])
            photo = request.files['photo']
            resume = request.files['resume']
            
            if not all([username, email, password, photo, resume]):
                flash('All fields are required.')
                return redirect(url_for('login_signup'))
            
            if not allowed_file(photo.filename, {'png', 'jpg', 'jpeg'}):
                flash('Invalid photo format. Please use PNG or JPG.')
                return redirect(url_for('login_signup'))
            
            if not allowed_file(resume.filename, {'pdf'}):
                flash('Invalid resume format. Please use PDF.')
                return redirect(url_for('login_signup'))
            
            try:
                photo_filename = secure_filename(photo.filename)
                resume_filename = secure_filename(resume.filename)
                
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))
                resume.save(os.path.join(app.config['UPLOAD_FOLDER'], resume_filename))
                
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, email, password, photo, resume) VALUES (?, ?, ?, ?, ?)',
                             (username, email, password, photo_filename, resume_filename))
                conn.commit()
                conn.close()
                
                flash('Signup successful! Please login.')
                return redirect(url_for('login_signup'))
                
            except sqlite3.IntegrityError:
                flash('Username or email already exists.')
                return redirect(url_for('login_signup'))
            except Exception as e:
                flash('An error occurred during signup.')
                return redirect(url_for('login_signup'))

        elif 'login' in request.form:  # Handle User Login
            email = request.form['email']
            password = request.form['password']

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            conn.close()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials.')
                return redirect(url_for('login_signup'))

    return render_template('login.html')

# Fix the company route
@app.route('/company', methods=['GET'])
def company_login_signup():
    return render_template('company.html')

# Redirect from /company.html to /company
@app.route('/company.html')
def redirect_to_company():
    return redirect(url_for('company_login_signup'))

# Company login and signup logic
@app.route('/company/login', methods=['POST'])
def company_login():
    email = request.form['email']
    password = request.form['password']

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM companies WHERE email = ?', (email,))
    company = cursor.fetchone()
    conn.close()

    if company and check_password_hash(company['password'], password):
        session['company_id'] = company['id']
        session['company_name'] = company['company_name']
        return redirect(url_for('company_dashboard'))
    else:
        flash('Invalid credentials.')
        return redirect(url_for('company_login_signup'))

@app.route('/company/signup', methods=['POST'])
def company_signup():
    company_name = request.form['company_name']
    email = request.form['email']
    password = generate_password_hash(request.form['password'])
    logo = request.files['logo']
    policy = request.files['policy']
    
    if not all([company_name, email, password, logo, policy]):
        flash('All fields are required.')
        return redirect(url_for('company_login_signup'))
    
    if not allowed_file(logo.filename, {'png', 'jpg', 'jpeg'}):
        flash('Invalid logo format. Please use PNG or JPG.')
        return redirect(url_for('company_login_signup'))
    
    if not allowed_file(policy.filename, {'pdf'}):
        flash('Invalid policy document format. Please use PDF.')
        return redirect(url_for('company_login_signup'))
    
    try:
        logo_filename = secure_filename(logo.filename)
        policy_filename = secure_filename(policy.filename)
        
        logo.save(os.path.join(app.config['UPLOAD_FOLDER'], logo_filename))
        policy.save(os.path.join(app.config['UPLOAD_FOLDER'], policy_filename))
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO companies (company_name, email, password, logo, policy_doc) VALUES (?, ?, ?, ?, ?)',
                     (company_name, email, password, logo_filename, policy_filename))
        conn.commit()
        conn.close()
        
        flash('Company registration successful! Please login.')
        return redirect(url_for('company_login_signup'))
        
    except sqlite3.IntegrityError:
        flash('Company name or email already exists.')
        return redirect(url_for('company_login_signup'))
    except Exception as e:
        flash('An error occurred during registration.')
        return redirect(url_for('company_login_signup'))

if __name__ == '__main__':
    app.run(debug=True)

