from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import requests

url = 'https://syntalix-mail.onrender.com/api'

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
    
    cursor.execute('''
CREATE TABLE IF NOT EXISTS Job_Status (
    Job_ID INTEGER PRIMARY KEY,
    Status TEXT DEFAULT 'Open',
    FOREIGN KEY (Job_ID) REFERENCES job_listings(id) ON DELETE CASCADE
)
''')
    
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
            email = f"{username}@syntalix.user"
            orignal_password = request.form['password']
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
                flash(uploadCredentialsfForMail(username,email,orignal_password))
                return redirect(url_for('login_signup'))
                
            except sqlite3.IntegrityError:
                flash('Username or email already exists.')
                return redirect(url_for('login_signup'))
            except Exception as e:
                flash('An error occurred during signup.')
                return redirect(url_for('login_signup'))

        elif 'login' in request.form:  # Handle User Login
            email = f"{request.form['username']}@syntalix.user"
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
BASE_URL = "https://syntalix-mail.onrender.com/api"

# 1. Signup
def uploadCredentialsfForMail(username,email,password):
    url = f"{BASE_URL}/signup"
    payload = {
        "username": username,
        "email": email,
        "password": password,
        "type": "user"
    }
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        print("Signup successful!")
    else:
        print("Failed to signup:", response.json().get("message"))


# Add this new route to check application status
@app.route('/check_application/<int:job_id>')
def check_application(job_id):
    if 'user_id' not in session:
        return jsonify({'applied': False})
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id FROM applications 
        WHERE job_id = ? AND user_id = ?
    ''', (job_id, session['user_id']))
    application = cursor.fetchone()
    conn.close()
    
    return jsonify({'applied': application is not None})

# Modify the dashboard route to include application status
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
    
    # Get all job listings and check if user has applied
    cursor.execute('''
        SELECT j.*, COUNT(a.id) as application_count 
    FROM job_listings j 
    LEFT JOIN applications a ON j.id = a.job_id 
    JOIN Job_Status s ON j.id = s.Job_ID 
    WHERE j.company_id = ? AND s.Status = 'Open'
    GROUP BY j.id 
    ORDER BY j.created_at DESC
    ''', (session['user_id'],))
    jobs = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         user=user,
                         jobs=jobs,
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
    email = f"{username}@syntalix.user"
    
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




@app.route('/apply', methods=['POST'])
def apply():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login to apply'})
    
    data = request.get_json()
    job_id = data.get('job_id')
    cover_letter = data.get('cover_letter')
    
    if not all([job_id, cover_letter]):
        return jsonify({'success': False, 'message': 'Missing required fields'})
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO applications (job_id, user_id, cover_letter) VALUES (?, ?, ?)',
                      (job_id, session['user_id'], cover_letter))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Application submitted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out successfully.')
    return redirect('/')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(413)
def file_too_large(e):
    flash('File too large. Maximum size is 16MB.')
    return redirect(url_for('dashboard'))
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
    email = f"{request.form['company_name']}.company@syntalix.user"
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
    email = f"{company_name}.company@syntalix.user"
    orignal_password = request.form['password']
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
        uploadCredentialsfForMail(company_name,email,orignal_password)
        return redirect(url_for('company_login_signup'))
        
    except sqlite3.IntegrityError:
        flash('Company name or email already exists.')
        return redirect(url_for('company_login_signup'))
    except Exception as e:
        flash('An error occurred during registration.')
        return redirect(url_for('company_login_signup'))
from werkzeug.security import check_password_hash

from werkzeug.security import check_password_hash

@app.route('/open_mail', methods=['GET', 'POST'])
def open_mail():
    # Check if the user is logged in
    if 'user_id' in session:
        # Fetch the user's email and password hash from the SQLite3 database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT email, password FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()

        if user:
            email = user['email']
            hashed_password = user['password']

            # If the form is submitted, check the password entered
            if request.method == 'POST':
                entered_password = request.form['password']
                if check_password_hash(hashed_password, entered_password):
                    # If the entered password matches the hashed password
                    return redirect(f"https://syntalix-mail.onrender.com/api/login/direct?email={email}&password={entered_password}")
                else:
                    flash('Incorrect password. Please try again.')
                    return redirect(url_for('open_mail'))

            # If it's a GET request, render a form to enter the password
            return render_template('password_prompt.html', email=email)
        else:
            flash('Unable to fetch user email and password.')
            return redirect(url_for('dashboard'))
    else:
        flash('Please login to access the email service.')
        return redirect(url_for('login_signup'))
        
@app.route('/open_company_mail', methods=['GET', 'POST'])
def open_company_mail():
    # Check if the company is logged in
    if 'company_id' in session:
        # Fetch the company's email and password hash from the SQLite3 database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT email, password FROM companies WHERE id = ?', (session['company_id'],))
        company = cursor.fetchone()
        conn.close()

        if company:
            company_email = company['email']
            hashed_company_password = company['password']

            # If the form is submitted, check the password entered
            if request.method == 'POST':
                entered_password = request.form['password']
                if check_password_hash(hashed_company_password, entered_password):
                    # If the entered password matches the hashed password
                    return redirect(f"https://syntalix-mail.onrender.com/api/login/direct?email={company_email}&password={entered_password}")
                else:
                    flash('Incorrect password. Please try again.')
                    return redirect(url_for('open_company_mail'))

            # If it's a GET request, render a form to enter the password
            return render_template('password_prompt.html', email=company_email)
        else:
            flash('Unable to fetch company email and password.')
            return redirect(url_for('dashboard'))
    else:
        flash('Please login to access the company email service.')
        return redirect(url_for('login_signup'))


# Add this new route to your app.py
@app.route('/company/dashboard')
def company_dashboard():
    if not session.get('company_id'):
        return redirect(url_for('company_login_signup'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get company information
    cursor.execute('SELECT * FROM companies WHERE id = ?', (session['company_id'],))
    company = cursor.fetchone()
    
    # Get all job listings for this company, along with application counts and job statuses (job_id and status)
    cursor.execute('''
        SELECT j.*, COUNT(a.id) as application_count, js.job_id, js.status as job_status
        FROM job_listings j 
        LEFT JOIN applications a ON j.id = a.job_id 
        LEFT JOIN job_status js ON j.id = js.job_id  -- Join with job_status table
        WHERE j.company_id = ? 
        GROUP BY j.id 
        ORDER BY j.created_at DESC''', 
        (session['company_id'],))
    job_listings = cursor.fetchall()
    
    # Get all applications for company's job listings
    cursor.execute('''
        SELECT a.*, j.title as job_title, u.username, u.email, u.resume
        FROM applications a
        JOIN job_listings j ON a.job_id = j.id
        JOIN users u ON a.user_id = u.id
        WHERE j.company_id = ?
        ORDER BY a.created_at DESC''',
        (session['company_id'],))
    applications = cursor.fetchall()
    
    conn.close()
    
    return render_template('company_dashboard.html',
                         company=company,
                         job_listings=job_listings,
                         applications=applications)

# Add these additional company-related routes
@app.route('/company/post-job', methods=['POST'])
def post_job():
    if not session.get('company_id'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    # Get all form fields
    title = request.form.get('job_title', '')
    description = request.form.get('description', '')
    requirements = request.form.get('requirements', '')
    salary_range = request.form.get('salary_range', '')
    location = request.form.get('location', '')
    
    # Print received data for debugging
    print("Received job posting data:")
    print(f"Title: {title}")
    print(f"Description: {description}")
    print(f"Requirements: {requirements}")
    print(f"Salary Range: {salary_range}")
    print(f"Location: {location}")
    
    # Check individual fields and create detailed error message
    missing_fields = []
    if not title:
        missing_fields.append('title')
    if not description:
        missing_fields.append('description')
    if not requirements:
        missing_fields.append('requirements')
    
    if missing_fields:
        error_message = f"Missing required fields: {', '.join(missing_fields)}"
        print(error_message)  # Print error for debugging
        return jsonify({'success': False, 'message': error_message})
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Print SQL data before insertion for debugging
        print(f"Attempting to insert job with company_id: {session['company_id']}")
        
        # Insert into job_listings first
        cursor.execute('''
            INSERT INTO job_listings 
            (company_id, title, description, requirements, salary_range, location)
            VALUES (?, ?, ?, ?, ?, ?)''',
            (session['company_id'], title, description, requirements, salary_range, location))
        
        # Get the ID of the newly inserted job
        job_id = cursor.lastrowid
        
        # Insert into Job_Status table with default 'Open' status
        cursor.execute('''
            INSERT INTO Job_Status (Job_ID, Status)
            VALUES (?, ?)''',
            (job_id, 'Open'))
        
        conn.commit()
        conn.close()
        
        print("Job posted successfully with status tracking")
        return jsonify({
            'success': True, 
            'message': 'Job posted successfully',
            'data': {
                'title': title,
                'description': description,
                'requirements': requirements,
                'salary_range': salary_range,
                'location': location,
                'status': 'Open'
            }
        })
    except Exception as e:
        print(f"Error posting job: {str(e)}")
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500

@app.route('/close-job/<int:job_id>', methods=['POST'])
def close_job(job_id):
    if not session.get('company_id'):
        return redirect(url_for('company_login_signup'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Update the job status to 'Closed' in the job_status table
    cursor.execute('''
        UPDATE job_status 
        SET status = 'Closed' 
        WHERE job_id = ? AND status = 'Open'
    ''', (job_id,))
    
    # Commit the changes and close the connection
    conn.commit()
    conn.close()

    # Redirect to company dashboard after updating the status
    return redirect(url_for('company_dashboard'))

@app.route('/company/update-application-status', methods=['POST'])
def update_application_status():
    if not session.get('company_id'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    application_id = request.form.get('application_id')
    new_status = request.form.get('status')
    entered_password = request.form.get('password')
    
    if not all([application_id, new_status, entered_password]):
        return jsonify({'success': False, 'message': 'Missing required fields'})
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Verify the company's password
        cursor.execute('SELECT password, company_name FROM companies WHERE id = ?', (session['company_id'],))
        company = cursor.fetchone()
        
        if not check_password_hash(company['password'], entered_password):
            return jsonify({'success': False, 'message': 'Invalid password'})
        
        # Fetch the applicant's email
        cursor.execute('''SELECT u.email 
                       FROM applications a
                       JOIN users u ON a.user_id = u.id
                       WHERE a.id = ?''', (application_id,))
        applicant_email = cursor.fetchone()[0]
        
        cursor.execute('UPDATE applications SET status = ? WHERE id = ?',
                      (new_status, application_id))
        
        
        # Send email notification
        company_name = company['company_name']
        job_id = cursor.execute('SELECT job_id FROM applications WHERE id = ?', (application_id,)).fetchone()[0]
        conn.commit()
        conn.close()
        curl_command = f"""curl -X POST https://syntalix-mail.onrender.com/api/send_email \
            -H 'Content-Type: application/json' \
            -d '{{
                \"email\": \"{company_name}.company@syntalix.user\",
                \"password\": \"{entered_password}\",
                \"to\": \"{applicant_email}\",
                \"subject\": \"Application Status Update for Job ID {job_id}\",
                \"content\": \"Application Status: {new_status}\"
            }}'"""
        
        os.system(curl_command)
        
        flash("Application status updated successfully.", "success")  # Flash success message
        return redirect(url_for('company_dashboard'))  # Redirect to the dashboard or desired page
    except Exception as e:
        flash("An error occurred while updating the application status.", "danger")  # Flash error message
        return redirect(url_for('company_dashboard')) 

@app.route('/company/logout')
def company_logout():
    session.pop('company_id', None)
    session.pop('company_name', None)
    return redirect(url_for('company_login_signup'))

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if email == 'admin@soujash.com' and password == 'admin@soujash':
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials')
            return redirect(url_for('admin_login'))
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    schema_info = {}
    for table in tables:
        table_name = table['name']
        cursor.execute(f"PRAGMA table_info({table_name});")
        columns = cursor.fetchall()
        schema_info[table_name] = columns
    
    conn.close()
    return render_template('admin.html', schema_info=schema_info, active_tab='schema')

@app.route('/admin/tables')
def admin_tables():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    table_data = {}
    for table in tables:
        table_name = table['name']
        cursor.execute(f"PRAGMA table_info({table_name});")
        columns = cursor.fetchall()
        
        visible_columns = [col['name'] for col in columns if col['name'].lower() != 'password']
        columns_str = ', '.join(visible_columns)
        cursor.execute(f"SELECT {columns_str} FROM {table_name}")
        rows = cursor.fetchall()
        
        # Get primary key column name
        primary_key = next((col['name'] for col in columns if col['pk'] == 1), 'id')
        
        table_data[table_name] = {
            'columns': visible_columns,
            'rows': rows,
            'primary_key': primary_key
        }
    
    conn.close()
    return render_template('admin.html', table_data=table_data, active_tab='tables')

@app.route('/admin/delete/<table_name>/<int:record_id>', methods=['POST'])
def delete_record(table_name, record_id):
    if not session.get('admin'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get primary key column name
        cursor.execute(f"PRAGMA table_info({table_name});")
        columns = cursor.fetchall()
        primary_key = next((col['name'] for col in columns if col['pk'] == 1), 'id')
        
        # Execute delete query
        cursor.execute(f"DELETE FROM {table_name} WHERE {primary_key} = ?", (record_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': f'Record deleted successfully from {table_name}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))


if __name__ == '__main__':
    app.run(debug=True)

