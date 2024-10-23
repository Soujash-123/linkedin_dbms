from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure secret key in production

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
    
    # Posts table
    cursor.execute('''CREATE TABLE IF NOT EXISTS posts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        title TEXT NOT NULL,
                        content TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    conn.commit()
    conn.close()

init_db()

def get_db():
    """Helper function to get database connection"""
    conn = sqlite3.connect('jobportal.db')
    conn.row_factory = sqlite3.Row  # This enables column access by name: row['column_name']
    return conn

@app.route('/', methods=['GET', 'POST'])
def login_signup():
    if request.method == 'POST':
        if 'signup' in request.form:  # Handle Signup
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            photo = request.files['photo']
            resume = request.files['resume']
            
            # Validation
            if not all([username, email, password, photo, resume]):
                flash('All fields are required.')
                return redirect(url_for('login_signup'))
            
            # File validation
            if not allowed_file(photo.filename, {'png', 'jpg', 'jpeg'}):
                flash('Invalid photo format. Please use PNG or JPG.')
                return redirect(url_for('login_signup'))
            
            if not allowed_file(resume.filename, {'pdf'}):
                flash('Invalid resume format. Please use PDF.')
                return redirect(url_for('login_signup'))
            
            try:
                # Save files
                photo_filename = secure_filename(photo.filename)
                resume_filename = secure_filename(resume.filename)
                
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))
                resume.save(os.path.join(app.config['UPLOAD_FOLDER'], resume_filename))
                
                # Save to database
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
                flash('An error occurred during signup. Please try again.')
                return redirect(url_for('login_signup'))

        elif 'login' in request.form:  # Handle Login
            email = request.form['email']
            password = request.form['password']

            if not all([email, password]):
                flash('Email and password are required.')
                return redirect(url_for('login_signup'))

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password))
            user = cursor.fetchone()
            conn.close()

            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials. Please try again.')
                return redirect(url_for('login_signup'))
                
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login to access the dashboard.')
        return redirect(url_for('login_signup'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get user information
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    # Get user's posts
    cursor.execute('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],))
    posts = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         user=user,
                         posts=posts,
                         username=session['username'])

@app.route('/create_post', methods=['POST'])
def create_post():
    if 'user_id' not in session:
        flash('Please login to create a post.')
        return redirect(url_for('login_signup'))
    
    title = request.form.get('title')
    content = request.form.get('content')
    
    if not all([title, content]):
        flash('Title and content are required.')
        return redirect(url_for('dashboard'))
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)',
                      (session['user_id'], title, content))
        conn.commit()
        conn.close()
        flash('Post created successfully!')
    except Exception as e:
        flash('An error occurred while creating the post.')
    
    return redirect(url_for('dashboard'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please login to view your profile.')
        return redirect(url_for('login_signup'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        flash('Please login to update your profile.')
        return redirect(url_for('login_signup'))
    
    username = request.form.get('username')
    email = request.form.get('email')
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Update basic info
        cursor.execute('UPDATE users SET username = ?, email = ? WHERE id = ?',
                      (username, email, session['user_id']))
        
        # Handle photo upload
        if 'photo' in request.files:
            photo = request.files['photo']
            if photo and allowed_file(photo.filename, {'png', 'jpg', 'jpeg'}):
                photo_filename = secure_filename(photo.filename)
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))
                cursor.execute('UPDATE users SET photo = ? WHERE id = ?',
                             (photo_filename, session['user_id']))
        
        # Handle resume upload
        if 'resume' in request.files:
            resume = request.files['resume']
            if resume and allowed_file(resume.filename, {'pdf'}):
                resume_filename = secure_filename(resume.filename)
                resume.save(os.path.join(app.config['UPLOAD_FOLDER'], resume_filename))
                cursor.execute('UPDATE users SET resume = ? WHERE id = ?',
                             (resume_filename, session['user_id']))
        
        conn.commit()
        conn.close()
        
        session['username'] = username  # Update session with new username
        flash('Profile updated successfully!')
    except sqlite3.IntegrityError:
        flash('Username or email already exists.')
    except Exception as e:
        flash('An error occurred while updating your profile.')
    
    return redirect(url_for('profile'))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('login_signup'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(413)
def file_too_large(e):
    flash('File too large. Maximum size is 16MB.')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)