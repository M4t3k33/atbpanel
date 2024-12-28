from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from api_config import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'twoj-tajny-klucz-flask'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///panel.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(120))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
@login_manager.user_loader
def load_user(id):
    return db.session.get(Admin, int(id))  # Updated from Admin.query.get()
def get_bot_stats():
    headers = {'X-API-Key': BOT_API_KEY}
    try:
        response = requests.get(f'{BOT_API_URL}/bot/stats', headers=headers)
        return response.json()
    except:
        return {'error': 'Nie można połączyć z botem'}

@app.route('/')
@login_required
def dashboard():
    stats = get_bot_stats()
    return render_template('dashboard.html', stats=stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = Admin.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Nieprawidłowe dane logowania')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/premium/add', methods=['POST'])
@login_required
def add_premium():
    headers = {
        'X-API-Key': BOT_API_KEY,
        'Content-Type': 'application/json'
    }
    response = requests.post(f'{BOT_API_URL}/bot/premium/add', 
                           headers=headers, 
                           json=request.json)
    return jsonify(response.json())

# Dodaj nowe endpointy
@app.route('/api/tickets/list')
@login_required
def list_tickets():
    headers = {'X-API-Key': BOT_API_KEY}
    response = requests.get(f'{BOT_API_URL}/bot/tickets/list', headers=headers)
    return jsonify(response.json())

@app.route('/api/users/list')
@login_required
def list_users():
    headers = {'X-API-Key': BOT_API_KEY}
    response = requests.get(f'{BOT_API_URL}/bot/users/list', headers=headers)
    return jsonify(response.json())

@app.route('/api/bot/announcement', methods=['POST'])
@login_required
def send_announcement():
    headers = {'X-API-Key': BOT_API_KEY}
    response = requests.post(f'{BOT_API_URL}/bot/announcement', 
                           headers=headers,
                           json=request.json)
    return jsonify(response.json())

@app.route('/api/stats')
@login_required
def get_stats():
    headers = {'X-API-Key': BOT_API_KEY}
    try:
        response = requests.get(f'{BOT_API_URL}/bot/stats', headers=headers)
        return jsonify(response.json())
    except requests.exceptions.RequestException:
        return jsonify({
            'premium_users': 0,
            'active_tickets': 0,
            'total_members': 0,
            'graphic_users': 0,
            'error': 'Could not connect to bot'
        })


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Tworzenie domyślnego admina
        if not Admin.query.filter_by(username=ADMIN_USERNAME).first():
            admin = Admin(username=ADMIN_USERNAME)
            admin.set_password(ADMIN_PASSWORD)
            db.session.add(admin)
            db.session.commit()

    app.run(host='0.0.0.0', port=5001)
