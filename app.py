from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Replace with a strong secret key

# Database configuration for MySQL on XAMPP
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/visionguard_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define the User model to map to `user_table` in the database
class User(db.Model):
    __tablename__ = 'user_table'
    
    # Column definitions matching your table structure
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    creat_at = db.Column(db.DateTime, default=datetime.utcnow)  # Matches the default of current timestamp

    def __repr__(self):
        return f"<User {self.username}>"

# Index Route (redirects to login)
@app.route('/')
def index():
    return redirect(url_for('login'))

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Cari user berdasarkan username
        user = User.query.filter_by(username=username).first()
        
        # Cek apakah user ada dan password cocok
        if user and check_password_hash(user.password, password):
            session['loggedin'] = True
            session['user_id'] = user.user_id
            session['username'] = user.username
            return redirect(url_for('home'))
        else:
            flash('Username atau password salah. Silakan coba lagi.')
    
    return render_template('login.html')



# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Cek jika password dan verifikasi password cocok
        if password != confirm_password:
            flash('Password dan Verifikasi Password tidak cocok. Silakan coba lagi.')
            return redirect(url_for('register'))
        
        # Hash password sebelum menyimpannya
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Tambahkan user baru ke database
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        # flash('Anda berhasil mendaftar! Silakan login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')


# Home Route
@app.route('/home')
def home():
    # Debugging: check if session variables are set
    print("Session loggedin:", session.get('loggedin'))
    
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    else:
        return redirect(url_for('login'))

# Additional Routes for Other Pages
@app.route('/cnn_results')
def cnn_results():
    # Placeholder route for CNN Results page
    return render_template('cnn_results.html')  # Create cnn_results.html in templates

@app.route('/classification')
def classification():
    # Placeholder route for Classification page
    return render_template('classification.html')  # Create classification.html in templates


# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Run the application
if __name__ == '__main__':
    app.run(debug=True)
