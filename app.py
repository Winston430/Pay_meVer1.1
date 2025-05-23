import os
import openai
import random
import string
import base64
import requests
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from babel.numbers import format_currency
from flask_wtf.csrf import CSRFProtect
from datetime import datetime,timezone, timedelta
from flask_login import login_required, current_user, login_user, logout_user, UserMixin
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired
from flask_mail import Mail, Message
from sqlalchemy.orm import validates
from itsdangerous import URLSafeTimedSerializer
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_cors import CORS
from forex_python.converter import CurrencyRates
import uuid
from flask import Blueprint
from decimal import InvalidOperation, Decimal
from functools import wraps
from flask import abort
from wtforms import StringField, PasswordField, BooleanField, SelectField, DecimalField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, Optional, NumberRange, ValidationError
from twilio.rest import Client
from urllib.parse import urljoin
from apscheduler.schedulers.background import BackgroundScheduler
from services.mix import mix_by_yas_bp
from services.airtel import airtel_bp
from services.mpesa import mpesa_bp
from services.crdb import crdb_bp
from services.nmb import nmb_bp
from services.equity import equity_bp
from services.absa import absa_bp
from services.halo import halo_bp
from flask_dance.contrib.google import make_google_blueprint, google



# Initialize App
app = Flask(__name__)


app.register_blueprint(mix_by_yas_bp, url_prefix='/mix')
app.register_blueprint(airtel_bp, url_prefix='/airtel')
app.register_blueprint(mpesa_bp, url_prefix='/mpesa')
app.register_blueprint(crdb_bp, url_prefix='/crdb')
app.register_blueprint(nmb_bp, url_prefix='/nmb')
app.register_blueprint(equity_bp, url_prefix='/equity')
app.register_blueprint(absa_bp, url_prefix='/absa')
app.register_blueprint(halo_bp, url_prefix='/halo')


admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

MOBILE_MONEY_API = "http://localhost:5001/api/v1/mobile/transfer"
BANK_API = "http://localhost:5002/api/v1/bank/transfer"

API_TIMEOUT = 3


# Security configurations
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True
)

CORS(app, supports_credentials=True)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'tonflixtz@gmail.com'
app.config['MAIL_PASSWORD'] = 'admin'
app.config['SECRET_KEY'] = 'e98f5b5db98ac7802d515335427b7a7fe5fb3176242df1bb0bcaddf32f3449bd'
app.config['SECURITY_PASSWORD_SALT'] = '20052oo5Wizzy9264'


mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

#app.config['BEEM_API_KEY'] = '2de547aa9cbb5729'
#app.config['BEEM_SECRET'] = 'YTA2OTRlYjkwYTQxNzdlNTk2YjZiNDY3ZmU2ZjNiMzVlYmFhMjIyNzRmMzgxMWYxYjhkYTVlZTUwMjA3MWIwNQ=='
#app.config['BEEM_SENDER_ID'] = 'INFO'


# Add Africa's Talking config:
app.config['AT_API_KEY'] = 'atsk_970090284423d62fd1e7466cfcfa4aecee11e37021a69d7e976a77b1e474677cde68f6f7'
app.config['AT_USERNAME'] = 'winstonwizboy@gmail.com'
app.config['AT_SENDER_ID'] = 'PayMETZ'  # Your approved shortcode or alphanumeric

# Configure Google OAuth
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "your-google-client-id")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "your-google-client-secret")

google_blueprint = make_google_blueprint(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    scope=["profile", "email"],
    redirect_to="google_login"
)

app.register_blueprint(google_blueprint, url_prefix="/google_login")


# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'payme.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = False

# Initialize extensions
csrf = CSRFProtect(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Models
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text)
    is_bot = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('chat_messages', lazy=True))

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    last_login = db.Column(db.DateTime)
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    login_count = db.Column(db.Integer, default=0)
    username = db.Column(db.String(80), unique=True, nullable=False)
    theme = db.Column(db.String(20), default='light')
    language = db.Column(db.String(10), default='en')
    currency = db.Column(db.String(10), default='TZS')
    email = db.Column(db.String(120), unique=True, nullable=False)
    email_transactions = db.Column(db.Boolean, default=True)
    email_notifications = db.Column(db.Boolean, default=True)
    email_newsletter = db.Column(db.Boolean, default=True)
    email_promotions = db.Column(db.Boolean, default=True)
    push_transactions = db.Column(db.Boolean, default=True)
    push_security = db.Column(db.Boolean, default=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    avatar = db.Column(db.String(255), default='default_quantum.png')
    wallet_balance = db.Column(db.Numeric(10, 2), default=0.00, nullable=False)
    total_balance = db.Column(db.Float, default=0.0)

    transactions = db.relationship(
        'Transaction', 
        foreign_keys='[Transaction.user_id]',
        backref='transaction_user',
        lazy=True
    )
    
    sent_transactions = db.relationship(
        'Transaction',
        foreign_keys='[Transaction.sender_id]',
        backref='transaction_sender',
        lazy=True
    )
    
    received_transactions = db.relationship(
        'Transaction',
        foreign_keys='[Transaction.recipient_id]',
        backref='transaction_recipient',
        lazy=True
    )    

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def update_balances(self):
        """Update all balance fields"""
        payment_methods = PaymentMethod.query.filter_by(user_id=self.id).all()
        self.total_balance = sum(pm.balance for pm in payment_methods) + float(self.wallet_balance)
        db.session.add(self)



class CurrencyConversion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Float)
    from_currency = db.Column(db.String(3))
    to_currency = db.Column(db.String(3))
    rate = db.Column(db.Float)
    converted_amount = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('currency_conversions', lazy=True))

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)  # 'transfer', 'deposit', 'withdrawal', etc.
    status = db.Column(db.String(20), default='pending')  # 'pending', 'completed', 'failed'
    reference = db.Column(db.String(100), unique=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(255))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    quantum_id = db.Column(db.String(64))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sender_balance_after = db.Column(db.Float)
    recipient_balance_after = db.Column(db.Float)
    
    # Relationships
    user = db.relationship(
        'User', 
        foreign_keys=[user_id],
        back_populates='transactions'
    )
    
    sender = db.relationship(
        'User',
        foreign_keys=[sender_id],
        back_populates='sent_transactions'
    )
    
    recipient = db.relationship(
        'User',
        foreign_keys=[recipient_id],
        back_populates='received_transactions'
    )
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

    def __repr__(self):
        return f'<Transaction {self.reference}>'
    


class PaymentMethod(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    method_type = db.Column(db.String(20))  # 'mobile' or 'bank'
    provider = db.Column(db.String(50))     # 'M-Pesa', 'Airtel Money', etc.
    account_number = db.Column(db.String(50))
    account_name = db.Column(db.String(100))
    balance = db.Column(db.Float, default=0.0)
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('payment_methods', lazy=True))


class OTPVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), nullable=False, index=True)  # Added index for faster lookups
    otp_code = db.Column(db.String(6), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=False) 
    attempts = db.Column(db.Integer, default=0)  # Track failed attempts
    
    @property
    def is_expired(self):
        return datetime.now(timezone.utc) > self.expires_at
    
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

class TransactionService:
    @staticmethod
    def generate_reference():
        return f"TX-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}"

    @staticmethod
    def create_transaction(user_id, amount, transaction_type, **kwargs):
        try:
            transaction = Transaction(
                user_id=user_id,
                amount=amount,
                transaction_type=transaction_type,
                reference=TransactionService.generate_reference(),
                status='pending',
                timestamp=datetime.utcnow(),
                **kwargs
            )
            db.session.add(transaction)
            return transaction
        except Exception as e:
            raise Exception(f"Failed to create transaction: {str(e)}")

    @staticmethod
    def complete_transaction(transaction_id):
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            raise Exception("Transaction not found")
        
        transaction.status = 'completed'
        db.session.commit()
        return transaction

    @staticmethod
    def fail_transaction(transaction_id, reason):
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            raise Exception("Transaction not found")
        
        transaction.status = 'failed'
        transaction.description = f"Failed: {reason}"
        db.session.commit()
        return transaction

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def init_db():
    with app.app_context():
        db.create_all()
        migrate_db()
        print("Database tables created/updated")
        create_test_user()

def migrate_db():
    """Handle database migrations for existing tables"""
    from sqlalchemy import inspect
    
    inspector = inspect(db.engine)
    columns = inspector.get_columns('user')
    existing_columns = {col['name'] for col in columns}
    
    # List of new columns we want to add
    new_columns = {
        'created_at': 'ALTER TABLE user ADD COLUMN created_at DATETIME',
        'last_login': 'ALTER TABLE user ADD COLUMN last_login DATETIME',
        'avatar': 'ALTER TABLE user ADD COLUMN avatar VARCHAR(255) DEFAULT "default_quantum.png"'
    }
    
    # Execute SQL for any missing columns
    with db.engine.connect() as conn:
        for col_name, sql in new_columns.items():
            if col_name not in existing_columns:
                conn.execute(sql)
                print(f"Added column {col_name} to user table")

def create_test_user():
    # Check if test user already exists
    test_user = User.query.filter_by(phone='+255621597522').first()
    if test_user:
        db.session.delete(test_user)
        db.session.commit()
    
    # Now create the test user
    test_user = User(
        is_admin=False,
        username='test',
        theme='light',
        language='en',
        currency='TZS',
        email='test@example.com',
        email_transactions=True,
        email_notifications=True,
        email_newsletter=True,
        email_promotions=True,
        push_transactions=True,
        push_security=True,
        phone='+255621597522',
        password_hash='scrypt:32768:8:1$4TUUhzt83aY3JAW1$2f6b8666fb149e990282454f1a7452f55f3c998355e158e99ac5b62cc536b2abe46c8bd2d5a83d59edd29f4441e5f9734779c7387c22e74d6227020b9b6ca95b',
        wallet_balance=0.0,
        total_balance=0.0,
        avatar='default_quantum.png'
    )
    db.session.add(test_user)
    db.session.commit()

def create_test_user():
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            email='admin@example.com',
            phone='+255700000000',
            password_hash=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()
    
def detect_network(phone_number):
    """Detect mobile network based on prefix"""
    prefixes = {
        '78': 'Airtel',
        '79': 'Airtel',
        '68': 'Airtel',
        '69': 'Airtel',
        '77': 'Yas',
        '61': 'Yas',
        '76': 'Vodacom',
        '75': 'Vodacom',
        '62': 'Halotel',
    }
    return prefixes.get(phone_number[:2], 'Unknown')

# Helper to get payment methods for the template
def get_user_payment_methods(user_id):
     # Order by default first, then maybe provider or name
     return PaymentMethod.query.filter_by(user_id=user_id)\
               .order_by(PaymentMethod.is_default.desc(), PaymentMethod.provider)\
               .all()



@property
def balance(self):
        """Calculate total balance from all payment methods"""
        return sum(method.balance for method in self.payment_methods) 


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def cleanup_otps():
    """Clean up expired OTPs"""
    with app.app_context():
        expired = OTPVerification.query.filter(
            OTPVerification.expires_at < datetime.utcnow()
        ).delete()
        db.session.commit()
        app.logger.info(f"Cleaned up {expired} expired OTPs")

# Schedule cleanup to run daily
scheduler = BackgroundScheduler()
scheduler.add_job(cleanup_otps, 'interval', hours=24)
scheduler.start()

def generate_otp(length=6):
    """Generate a secure OTP"""
    return ''.join(random.SystemRandom().choice(string.digits) for _ in range(length))

def send_otp_via_sms(phone_number, otp_code):
    """Send OTP via Africa's Talking SMS API"""
    try:
        # Clean phone number
        phone_number = phone_number.strip()
        if not phone_number.startswith('+'):
            phone_number = f"+255{phone_number.lstrip('0')}"  # Assuming Tanzania numbers
            
        # Prepare request
        url = 'https://api.africastalking.com/version1/messaging'
        headers = {
            'ApiKey': app.config['AT_API_KEY'],
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        
        payload = {
            'username': app.config['AT_USERNAME'],
            'to': phone_number,
            'message': f"Your PayMe verification code is: {otp_code}. Valid for 5 minutes.",
            'from': app.config['AT_SENDER_ID']
        }

        response = requests.post(url, headers=headers, data=payload, timeout=10)
        response.raise_for_status()
        
        # Check Africa's Talking response
        result = response.json()
        if result['SMSMessageData']['Recipients'][0]['status'] == 'Success':
            return True
        else:
            app.logger.error(f"Africa's Talking error: {result}")
            return False
            
    except requests.exceptions.RequestException as e:
        app.logger.error(f"SMS sending failed: {str(e)}")
        if hasattr(e, 'response') and e.response:
            app.logger.error(f"API Response: {e.response.text}")
        return False
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return False
    

def create_mock_balances(user_id, num_methods=3):
    """Generate fake payment methods with random balances for testing"""
    providers = {
        'mobile': ['M-Pesa', 'Airtel Money', 'Tigo Pesa', 'Halopesa'],
        'bank': ['CRDB', 'NMB', 'NBC', 'Stanbic']
    }

    # Delete existing methods (optional)
    PaymentMethod.query.filter_by(user_id=user_id).delete()

    # Create mobile money accounts
    for i in range(min(2, num_methods)):  # 2 mobile accounts
        db.session.add(PaymentMethod(
            user_id=user_id,
            method_type='mobile',
            provider=random.choice(providers['mobile']),
            account_number=f"+2557{random.randint(10000000, 99999999)}",
            account_name="Test User",
            balance=random.uniform(1000, 50000),
            is_default=(i == 0)
        ))

    # Create bank accounts
    for i in range(num_methods - 2):
        db.session.add(PaymentMethod(
            user_id=user_id,
            method_type='bank',
            provider=random.choice(providers['bank']),
            account_number=str(random.randint(1000000000, 9999999999)),
            account_name="TEST USER",
            balance=random.uniform(5000, 200000),
            is_default=False
        ))

    db.session.commit()


# Facebook OAuth
facebook_blueprint = make_facebook_blueprint(
    client_id="your-facebook-app-id",
    client_secret="your-facebook-app-secret",
    scope="email",
    redirect_to="facebook_login"
)
app.register_blueprint(facebook_blueprint, url_prefix="/facebook_login")


@validates('password_hash')
def validate_password_hash(self, key, value):
    if value.startswith('$2b$') or value.startswith('$2a$'):
        return value
    raise ValueError('Password must be hashed')

from blinker import Namespace

# Define the signal
signals = Namespace()
user_registered = signals.signal('user-registered')

@user_registered.connect
def on_user_registered(user, **extra):
    # Credit bonus
    default_wallet = PaymentMethod(
        user_id=user.id,
        balance=50000000.00,
        # ... other fields
    )
    db.session.add(default_wallet)
    db.session.commit()


@app.route('/api/chat', methods=['POST'])
def chat():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user = User.query.get(session['user_id'])
    data = request.get_json()
    message = data.get('message', '').strip()

    if not message:
        return jsonify({'error': 'Message cannot be empty'}), 400

    try:
        # Save user message
        user_message = ChatMessage(
            user_id=user.id,
            message=message,
            is_bot=False
        )
        db.session.add(user_message)
        
        # Generate response (using OpenAI as example)
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful financial assistant for PayMe app. Help users with transactions, payments, and account questions."},
                {"role": "user", "content": message}
            ]
        )
        bot_response = response.choices[0].message.content
        
        # Save bot response
        bot_message = ChatMessage(
            user_id=user.id,
            message=bot_response,
            is_bot=True
        )
        db.session.add(bot_message)
        db.session.commit()
        
        return jsonify({
            'response': bot_response,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    
@app.template_filter('format_currency')
def format_currency_filter(amount, currency='TZS', locale='en_US'):
    """Format currency using Babel"""
    return format_currency(amount, currency, locale=locale)

@app.route('/api/chat/history', methods=['GET'])
def chat_history():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    messages = ChatMessage.query.filter_by(user_id=session['user_id'])\
                  .order_by(ChatMessage.timestamp.asc())\
                  .limit(50)\
                  .all()
    
    return jsonify({
        'messages': [{
            'id': msg.id,
            'text': msg.message,
            'is_bot': msg.is_bot,
            'timestamp': msg.timestamp.isoformat()
        } for msg in messages]
    })


# Base template context processor for futuristic elements
@app.context_processor
def inject_futuristic():
    return dict(
        current_year=datetime.now().year,
        future_year=2060,
        quantum_loading=True,
        holographic_ui=True
    )

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # Pass WTForms form object if you define one for registration, else None
    # form = RegistrationForm() # Example

    if request.method == 'POST':
        is_ajax = request.headers.get('Accept') == 'application/json'
        submitted_phone_step1 = request.form.get('phone', '').strip() # Get phone early for potential non-AJAX errors

        try:
            # --- STEP 1: Phone Submission & OTP Sending ---
            if 'otp_verified' not in request.form:
                phone = submitted_phone_step1 # Use phone submitted in this step

                # Server-Side Validation
                if not phone or not phone.startswith('+255') or len(phone) != 13 or not phone[1:].isdigit():
                    error_msg = 'Please enter a valid Tanzanian phone number (e.g., +255712345678).'
                    if is_ajax:
                        return jsonify({'error': error_msg, 'field_errors': {'phone': error_msg}}), 400
                    else:
                        flash(error_msg, 'danger'); return render_template('register.html')

                if User.query.filter_by(phone=phone).first():
                    error_msg = 'This phone number is already registered.'
                    if is_ajax:
                        return jsonify({'error': error_msg, 'field_errors': {'phone': error_msg}}), 409 # 409 Conflict
                    else:
                        flash(error_msg, 'danger'); return render_template('register.html')

                # Generate OTP and Expiry
                otp_code = generate_otp()
                expires_at = datetime.now(timezone.utc) + timedelta(minutes=5) # Use timezone aware now

                # Store OTP Record (Corrected)
                otp_record = OTPVerification(
                    phone=phone,
                    otp_code=otp_code,
                    expires_at=expires_at # **FIXED**
                )
                db.session.add(otp_record)
                db.session.commit()

                # Send OTP SMS
                sms_sent = send_otp_via_sms(phone, otp_code)
                if not sms_sent:
                    logger.error(f"Failed to send OTP SMS to {phone}")
                    error_msg = 'Failed to send verification code via SMS. Please try again shortly.'
                    if is_ajax:
                        return jsonify({'error': error_msg}), 500
                    else:
                        flash(error_msg, 'danger'); return render_template('register.html')

                # Step 1 Success
                success_msg = 'Verification code sent to your phone number.'
                if is_ajax:
                    return jsonify({
                        'success': True,
                        'message': success_msg,
                        'next_step': 'verify_otp',
                        'phone': phone
                    }), 200
                else: # Fallback - less likely with current JS
                    flash(success_msg, 'info')
                    # Render showing step 2, passing phone number
                    return render_template('register.html', show_otp=True, phone=phone)

            # --- STEP 2: OTP Verification & User Creation ---
            else:
                # Get data from Step 2 form submission
                phone_from_step2 = request.form.get('phone') # From hidden field
                otp_code = request.form.get('otp_code', '').strip()
                username = request.form.get('username', '').strip()
                email = request.form.get('email', '').strip().lower() # Normalize email
                password = request.form.get('password', '').strip()
                confirm_password = request.form.get('confirm_password', '').strip()
                terms = request.form.get('terms') == 'on'

                # --- Validation ---
                field_errors = {}
                otp_record = None # Initialize otp_record

                # 1. Validate OTP
                if not otp_code or not otp_code.isdigit() or len(otp_code) != 6:
                    field_errors['otp'] = 'Please enter the 6-digit code.'
                else:
                    otp_record = OTPVerification.query.filter(
                        OTPVerification.phone == phone_from_step2,
                        OTPVerification.verified == False,
                        OTPVerification.expires_at > datetime.now(timezone.utc)
                    ).order_by(OTPVerification.created_at.desc()).first()

                    if not otp_record:
                        field_errors['otp'] = 'Invalid or expired OTP code. Please resend.'
                    elif otp_record.otp_code != otp_code:
                        field_errors['otp'] = 'Incorrect OTP code entered.'
                        otp_record.attempts += 1
                        db.session.add(otp_record)
                        # Commit attempt count immediately or wait until end? Let's wait.

                # 2. Validate Other Fields (only if OTP seems okay initially)
                if 'otp' not in field_errors:
                    if not username or len(username) < 3 or len(username) > 30 or not username.replace('_', '').isalnum():
                        field_errors['username'] = 'Username must be 3-30 chars (letters, numbers, _).'
                    elif User.query.filter(User.username.ilike(username)).first(): # Case-insensitive check
                        field_errors['username'] = 'Username is already taken.'

                    if not email or '@' not in email or '.' not in email.split('@')[-1]:
                        field_errors['email'] = 'Please enter a valid email address.'
                    elif User.query.filter(User.email.ilike(email)).first(): # Case-insensitive check
                        field_errors['email'] = 'This email address is already registered.'

                    if not password or len(password) < 8:
                        field_errors['password'] = 'Password must be at least 8 characters.'
                    elif password != confirm_password:
                        # Only add error to confirm_password if main password is long enough
                        if len(password) >= 8:
                            field_errors['confirm_password'] = 'Passwords do not match.'
                        # Otherwise, the password error is primary

                    if not terms:
                        field_errors['terms'] = 'You must agree to the terms and conditions.'

                # 3. Return if any errors found
                if field_errors:
                     # Commit OTP attempt count if it was incremented
                     if otp_record and 'otp' in field_errors and field_errors['otp'] == 'Incorrect OTP code entered.':
                          db.session.commit()
                     if is_ajax:
                        return jsonify({
                            'error': 'Please correct the errors highlighted below.',
                            'field_errors': field_errors
                        }), 400
                     else: # Non-AJAX fallback
                        for field, msg in field_errors.items(): flash(f"{msg}", 'danger')
                        # Pass submitted data back to repopulate form (WTForms simplifies this)
                        return render_template('register.html', show_otp=True, phone=phone_from_step2,
                                                submitted_username=username, submitted_email=email)

                # --- All Validations Passed ---
                # Mark OTP as verified
                otp_record.verified = True
                db.session.add(otp_record)

                # Create the new user
                new_user = User(
                    username=username,
                    email=email,
                    phone=phone_from_step2 # Use verified phone
                )
                new_user.set_password(password) # Hash the password
                db.session.add(new_user)

                # Commit user creation and OTP verification together
                db.session.commit()
                logger.info(f"New user registered: {username} (Phone: {phone_from_step2})")

                # Optional: Trigger post-registration actions
                # user_registered.send(new_user)

                # Registration Success
                success_msg = 'Account created successfully! Please log in.'
                if is_ajax:
                    return jsonify({
                        'success': True,
                        'message': success_msg,
                        'redirect': url_for('login')
                    }), 201 # 201 Created
                else: # Non-AJAX fallback
                    flash(success_msg, 'success')
                    return redirect(url_for('login'))

        # --- General Exception Handling ---
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}", exc_info=True)
            error_msg = "An unexpected error occurred during registration. Please try again."
            if is_ajax:
                return jsonify({'error': error_msg}), 500
            else:
                flash(error_msg, 'danger')
                # Pass original submitted phone if available
                return render_template('register.html', phone=submitted_phone_step1 or '')

    # --- Handle GET Request ---
    logger.debug("Rendering registration form (GET request)")
    return render_template('register.html') # Add form=form if using WTForms

@app.route('/register/success')
@login_required
def register_success():
    return render_template('register_success.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # If already logged in, redirect immediately
        return redirect(url_for('dashboard'))

    form = LoginForm() # Instantiate your login form

    # --- Handle POST Request ---
    if request.method == 'POST':
        is_ajax = request.headers.get('Accept') == 'application/json'

        # Try block for potential errors during processing
        try:
            # Use WTForms validation (even for AJAX)
            if form.validate_on_submit():
                # Form fields are valid (non-empty etc.)
                username_or_email = form.username.data.strip()
                password = form.password.data
                remember = form.remember.data

                # Attempt to find the user by username or email
                user = User.query.filter(
                    (User.username == username_or_email) | (User.email == username_or_email)
                ).first()

                # Validate user and password
                if user and user.check_password(password):
                    # --- LOGIN SUCCESS ---
                    login_user(user, remember=remember)
                    user.last_login = datetime.utcnow() # Update last login
                    db.session.commit()

                    next_page = request.args.get('next')
                    redirect_url = next_page or url_for('dashboard')

                    if is_ajax:
                        return jsonify({
                            'success': True, # Indicate success
                            'message': 'Login successful! Redirecting...', # Optional message
                            'redirect': redirect_url
                        }), 200 # OK status
                    else:
                        # Fallback for non-AJAX (less likely now)
                        flash('Login successful!', 'success')
                        return redirect(redirect_url)
                else:
                    # --- INVALID CREDENTIALS ---
                    error_message = "Invalid username or password"
                    field_errors = {
                        "username": "Invalid credentials", # Corresponds to input ID 'username'
                        "password": "Invalid credentials"  # Corresponds to input ID 'password'
                    }
                    if is_ajax:
                        return jsonify({
                            'error': error_message,
                            'field_errors': field_errors
                        }), 401 # Unauthorized status
                    else:
                        flash(error_message, 'danger')
                        # Re-render form, WTForms won't show these specific errors here
                        return render_template('login.html', title='Login', form=form)

            else:
                # --- FORM VALIDATION FAILED (e.g., empty fields) ---
                # WTForms validation failed before attempting login
                if is_ajax:
                    # Extract errors from WTForms
                    field_errors = {field: errors[0] for field, errors in form.errors.items()}
                    return jsonify({
                        'error': 'Please correct the errors below.',
                        'field_errors': field_errors
                    }), 400 # Bad Request status
                else:
                    # For non-AJAX, WTForms handles displaying errors automatically
                    # when rendering the template with the form object
                    flash('Please correct the errors in the form.', 'warning')
                    return render_template('login.html', title='Login', form=form)

        except Exception as e:
            # --- UNEXPECTED SERVER ERROR ---
            db.session.rollback() # Rollback potentially broken transactions
            app.logger.error(f"Login error: {str(e)}", exc_info=True) # Log the full error
            error_message = "An unexpected error occurred during login. Please try again later."
            if is_ajax:
                return jsonify({
                    'error': error_message
                    # Optionally add more details in development mode
                    # 'debug_error': str(e) if app.debug else None
                }), 500 # Internal Server Error status
            else:
                flash(error_message, 'danger')
                return render_template('login.html', title='Login', form=form)


    # --- Handle GET Request ---
    # Render the login page normally
    return render_template('login.html', title='Login', form=form)

@app.route("/google_login")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    
    try:
        resp = google.get("/oauth2/v2/userinfo")
        if resp.ok:
            user_info = resp.json()
            
            # Extract user data from Google response
            email = user_info["email"]
            google_id = user_info["id"]
            name = user_info.get("name", "")
            picture = user_info.get("picture", "")
            
            # Check if user exists in your database
            user = User.query.filter_by(email=email).first()
            
            if not user:
                # Create new user
                user = User(
                    username=email.split("@")[0],
                    email=email,
                    # Generate a random password (users will use Google to login)
                    password_hash=generate_password_hash(str(uuid.uuid4())),
                    phone="",  # You might want to collect this later
                    avatar=picture,
                    google_id=google_id
                )
                db.session.add(user)
                db.session.commit()
            
            # Log the user in
            login_user(user)
            
            flash("Logged in successfully with Google!", "success")
            return redirect(url_for("dashboard"))
        
        flash("Failed to fetch user info from Google", "danger")
        return redirect(url_for("login"))
    
    except Exception as e:
        flash(f"Google login error: {str(e)}", "danger")
        return redirect(url_for("login"))


@app.route("/facebook_login")
def facebook_login():
    if not facebook.authorized:
        return redirect(url_for("facebook.login"))
    
    resp = facebook.get("/me?fields=id,name,email")
    if resp.ok:
        user_info = resp.json()
        # Handle user authentication here
        return redirect(url_for("dashboard"))
    
    return "Failed to fetch user info", 400

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(user.email, salt=app.config['SECURITY_PASSWORD_SALT'])
            reset_url = url_for('reset_password', token=token, _external=True)
            
            msg = Message('Password Reset Request',
                          sender='noreply@example.com',
                          recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email.
'''
            mail.send(msg)
        
        flash('If an account with that email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))
    
    return render_template('reset_password_request.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=3600  # Expires after 1 hour
        )
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('reset_password_request'))
    
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(request.form['password'])
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/mock_balances')
@login_required
def mock_balances():
    create_mock_balances(current_user.id)
    flash("Mock balances generated!", "success")
    return redirect(url_for('dashboard'))

# Update all route protections to use @login_required consistently:
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        payment_methods = PaymentMethod.query.filter_by(user_id=current_user.id).all()
        total_balance = sum(m.balance for m in payment_methods if hasattr(m, 'balance'))
        
        transactions = Transaction.query.filter_by(user_id=current_user.id) \
                          .order_by(Transaction.timestamp.desc()) \
                          .limit(5).all()
        
        try:
            c = CurrencyRates()
            current_rate = c.get_rate('USD', 'TZS')
        except:
            current_rate = 2665.00
        
        return render_template(
            'dashboard.html',
            user_data=current_user,
            total_balance=total_balance,
            payment_methods=payment_methods,
            transactions=transactions,
            current_rate=current_rate
        )
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return render_template(
            'dashboard.html',
            user_data=current_user,
            total_balance=0,
            payment_methods=[],
            transactions=[],
            current_rate=2300.00
        )
    
# Remove all manual session checks and replace with @login_required
@app.route('/transfer', methods=['GET'])
@login_required
def transfer_form():
    try:
        payment_methods = get_user_payment_methods(current_user.id)
        # Calculate total balance *from these methods* for display
        total_balance = sum(method.balance for method in payment_methods if method.balance is not None)

        return render_template('transfer.html',
                               payment_methods=payment_methods,
                               total_balance=total_balance,
                               # Pass form object if using WTForms
                               # form=TransferForm()
                               )
    except Exception as e:
        logger.error(f"Error loading transfer form: {str(e)}", exc_info=True)
        flash('Could not load transfer page. Please try again.', 'danger')
        return redirect(url_for('dashboard'))


# === Route to process the transfer (AJAX POST) ===
@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    # Expecting JSON data from the frontend fetch call
    if not request.is_json:
        # If it's not JSON, return an error appropriate for an API endpoint
        logger.warning("Transfer endpoint received non-JSON request")
        return jsonify({'error': 'Invalid request format. Expected JSON.'}), 415 # Unsupported Media Type

    data = request.get_json()
    logger.debug(f"Received transfer data: {data}")

    # --- Input Extraction and Basic Validation ---
    from_account_id_str = data.get('from_account_id')
    to_account_id_str = data.get('to_account_id')
    amount_str = data.get('amount')
    description = data.get('description', '').strip() # Optional description

    field_errors = {}
    from_account_id = None
    to_account_id = None
    amount_decimal = None

    # Validate IDs
    try:
        if from_account_id_str: from_account_id = int(from_account_id_str)
        else: field_errors['from_account'] = 'Please select the source account.'
    except (ValueError, TypeError):
        field_errors['from_account'] = 'Invalid source account selected.'

    try:
        if to_account_id_str: to_account_id = int(to_account_id_str)
        else: field_errors['to_account'] = 'Please select the destination account.'
    except (ValueError, TypeError):
        field_errors['to_account'] = 'Invalid destination account selected.'

    # Validate Amount
    try:
        if amount_str is not None:
            # Use Decimal for precision with currency
            amount_decimal = Decimal(str(amount_str))
            if amount_decimal <= Decimal('0.00'):
                 field_errors['amount'] = 'Amount must be greater than zero.'
            elif amount_decimal < Decimal('100.00'): # Example minimum
                 field_errors['amount'] = 'Minimum transfer amount is 100 TZS.'
        else:
            field_errors['amount'] = 'Amount is required.'
    except (InvalidOperation, TypeError):
         field_errors['amount'] = 'Invalid amount entered. Please use numbers only.'

    # Validate self-transfer
    if from_account_id and to_account_id and from_account_id == to_account_id:
         field_errors['to_account'] = 'Cannot transfer funds to the same account.'
         # Optionally clear from_account error if it was just "required"
         if field_errors.get('from_account') == 'Please select the source account.':
             field_errors.pop('from_account', None)

    if field_errors:
        logger.info(f"Transfer validation failed: {field_errors}")
        return jsonify({
            'error': 'Please correct the errors below.',
            'field_errors': field_errors
        }), 400 # Bad Request

    # --- Fetch Accounts and Check Ownership/Balance ---
    try:
        # Ensure accounts exist AND belong to the current user
        from_account = PaymentMethod.query.filter_by(id=from_account_id, user_id=current_user.id).first()
        to_account = PaymentMethod.query.filter_by(id=to_account_id, user_id=current_user.id).first()

        if not from_account:
            logger.warning(f"Source account ID {from_account_id} not found or doesn't belong to user {current_user.id}")
            return jsonify({'error': 'Source account not found or invalid.'}), 404 # Not Found or 400 Bad Request
        if not to_account:
             logger.warning(f"Destination account ID {to_account_id} not found or doesn't belong to user {current_user.id}")
             return jsonify({'error': 'Destination account not found or invalid.'}), 404 # Not Found or 400 Bad Request

        # Check sufficient balance (using Decimal)
        if from_account.balance is None or Decimal(str(from_account.balance)) < amount_decimal:
            logger.warning(f"Insufficient balance for user {current_user.id} in account {from_account_id}. Has: {from_account.balance}, Needs: {amount_decimal}")
            return jsonify({
                'error': 'Insufficient funds in the selected source account.',
                 # Optionally map to 'amount' field for frontend display
                'field_errors': {'amount': f'Insufficient funds. Available: {from_account.balance:.2f} TZS'}
            }), 400 # Bad Request

    except Exception as e:
        logger.error(f"Error fetching accounts for transfer: {str(e)}", exc_info=True)
        return jsonify({'error': 'An error occurred while verifying accounts.'}), 500

    # --- Perform Transfer within a Database Transaction ---
    transaction_ref = None # Initialize in case of failure before assignment
    try:
        # Use db.session.begin() for context management (SQLAlchemy 1.4+)
        # or db.session.begin_nested() if needed, followed by db.session.commit() / rollback()
        with db.session.begin(): # Automatically handles commit/rollback on exit/exception
            # 1. Create Transaction Record (Pending)
            # Ensure amount is stored correctly (Float or Decimal in DB?) - Assuming Float here
            transfer_amount_float = float(amount_decimal)

            # Use TransactionService if it encapsulates logic, otherwise direct creation:
            transaction = Transaction(
                user_id=current_user.id, # User initiating the transfer
                amount=transfer_amount_float, # Amount being moved
                transaction_type='internal_transfer', # More specific type
                status='pending', # Start as pending
                reference=TransactionService.generate_reference(), # Generate unique ref
                description=description or f"Transfer from {from_account.provider} to {to_account.provider}",
                # Store relevant IDs for clarity, though not strictly necessary if only internal
                metadata={ # Store extra info if needed
                     'from_account_id': from_account.id,
                     'to_account_id': to_account.id,
                     'from_provider': from_account.provider,
                     'to_provider': to_account.provider
                 }
                # sender_id/recipient_id might not apply for internal account transfers
            )
            db.session.add(transaction)
            # Flush to get transaction ID if needed immediately, but commit later
            db.session.flush()
            transaction_ref = transaction.reference # Store reference for logging/response

            # 2. Update Balances (using Decimal)
            from_account.balance = Decimal(str(from_account.balance)) - amount_decimal
            to_account.balance = Decimal(str(to_account.balance)) + amount_decimal
            logger.info(f"Updating balances: From {from_account.id} new balance {from_account.balance}, To {to_account.id} new balance {to_account.balance}")

            # Add updated accounts to session
            db.session.add(from_account)
            db.session.add(to_account)

            # 3. Update Transaction Status to Completed
            transaction.status = 'completed'
            transaction.sender_balance_after = float(from_account.balance) # Store final balances if needed
            transaction.recipient_balance_after = float(to_account.balance) # Assuming these fields exist
            db.session.add(transaction)

        # --- If `with db.session.begin()` exits without exception, it commits ---
        logger.info(f"Transfer {transaction_ref} completed successfully for user {current_user.id}")

        # --- Success JSON Response ---
        return jsonify({
            'success': True,
            'message': f'Successfully transferred {amount_decimal:.2f} TZS.',
            'transaction': { # Send back some details if useful for frontend
                'reference': transaction_ref,
                'amount': transfer_amount_float,
                'from_account_new_balance': float(from_account.balance),
                'to_account_new_balance': float(to_account.balance)
            }
        }), 200 # OK

    except Exception as e:
        # The 'with db.session.begin():' block automatically rolls back on exception
        logger.error(f"Transfer failed for ref {transaction_ref} (User: {current_user.id}): {str(e)}", exc_info=True)

        # Optionally mark the transaction as failed if it was created
        if transaction_ref:
             try:
                 # Find the pending transaction outside the failed 'with' block
                 failed_tx = Transaction.query.filter_by(reference=transaction_ref, status='pending').first()
                 if failed_tx:
                     failed_tx.status = 'failed'
                     failed_tx.description = f"Failed: {str(e)[:250]}" # Truncate error message
                     db.session.commit() # Commit the failure status
             except Exception as log_fail_e:
                 logger.error(f"Failed to mark transaction {transaction_ref} as failed: {str(log_fail_e)}")
                 db.session.rollback() # Rollback attempt to mark as failed

        # --- Failure JSON Response ---
        return jsonify({
            'error': 'Transfer failed due to an internal error. Please try again later.'
            # Avoid sending raw exception 'e' to the client for security
        }), 500 # Internal Server Error

@app.route('/bank_transaction', methods=['GET', 'POST'])
@login_required
def bank_transaction():
    # Get only BANK payment methods for current user
    user_bank_accounts = PaymentMethod.query.filter_by(
        user_id=current_user.id,
        method_type='bank'
    ).all()

    if request.method == 'POST':
        try:
            # Get form data
            from_account_id = request.form.get('payment_method_id')
            to_account_number = request.form.get('bank_account').strip()
            amount = float(request.form.get('amount'))
            recipient_name = request.form.get('recipient_name').strip()
            reference = request.form.get('reference', '').strip()

            # Validate
            if not all([from_account_id, to_account_number, amount, recipient_name]):
                flash('All fields are required', 'danger')
                return redirect(url_for('bank_transaction'))

            if amount <= 0:
                flash('Amount must be positive', 'danger')
                return redirect(url_for('bank_transaction'))

            # Get sender account
            from_account = PaymentMethod.query.filter_by(
                id=from_account_id,
                user_id=current_user.id
            ).first_or_404()

            # Check sufficient balance
            if from_account.balance < amount:
                flash('Insufficient balance', 'danger')
                return redirect(url_for('bank_transaction'))

            # Prevent self-transfer
            if from_account.account_number == to_account_number:
                flash('Cannot transfer to your own account', 'danger')
                return redirect(url_for('bank_transaction'))

            # Process transaction
            db.session.begin()
            try:
                # Deduct from sender
                from_account.balance -= amount
                db.session.add(from_account)

                # Record transaction
                new_transaction = Transaction(
                    user_id=current_user.id,
                    payment_method_id=from_account_id,
                    amount=amount,
                    description=f"Bank transfer to {recipient_name}",
                    status='completed',  # or 'pending' if you need approval
                    transaction_type='bank_transfer',
                    reference=reference,
                    metadata={
                        'recipient_name': recipient_name,
                        'recipient_account': to_account_number,
                        'sender_account': from_account.account_number,
                        'bank_name': from_account.bank_name
                    }
                )
                db.session.add(new_transaction)

                # Update user's total balance if needed
                current_user.total_balance -= amount
                db.session.add(current_user)

                db.session.commit()

                flash('Bank transfer completed successfully!', 'success')
                return redirect(url_for('transactions'))

            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Bank transfer error: {str(e)}')
                flash('Transfer failed. Please try again.', 'danger')
                return redirect(url_for('bank_transaction'))

        except ValueError:
            flash('Invalid amount entered', 'danger')
            return redirect(url_for('bank_transaction'))

    return render_template('bank_transaction.html', 
                         payment_methods=user_bank_accounts,
                         current_balance=current_user.total_balance)

@app.route('/send-money', methods=['GET', 'POST'])
@login_required
def send_money():
    if request.method == 'POST':
        try:
            # Get form data
            amount = float(request.form['amount'])
            recipient_type = request.form['recipient_type']
            recipient_number = request.form['recipient_number']
            network_or_bank = request.form.get('network_or_bank')
            notes = request.form.get('notes', '')
            
            # Validate amount
            if amount <= 0:
                flash('Amount must be positive', 'danger')
                return redirect(url_for('send_money'))
            
            # Check sender's total balance
            payment_methods = PaymentMethod.query.filter_by(user_id=current_user.id).all()
            total_balance = sum(m.balance for m in payment_methods)
            
            if total_balance < amount:
                flash('Insufficient balance in your wallet', 'danger')
                return redirect(url_for('send_money'))
            
            # Process transfer based on recipient type
            if recipient_type == 'mobile':
                # Mobile money transfer
                # In a real app, you would call mobile money API here
                # For now, we'll just deduct from wallet
                deduct_from_wallet(current_user.id, amount)
                
                # Record transaction
                transaction = Transaction(
                    user_id=current_user.id,
                    amount=-amount,
                    description=f"Mobile money to {recipient_number} ({network_or_bank})",
                    transaction_type='mobile_transfer',
                    status='completed'
                )
                db.session.add(transaction)
                db.session.commit()
                
                flash(f'Successfully sent {amount:.2f} TZS to {recipient_number}', 'success')
                
            elif recipient_type == 'bank':
                # Bank transfer
                # In a real app, you would call bank API here
                deduct_from_wallet(current_user.id, amount)
                
                transaction = Transaction(
                    user_id=current_user.id,
                    amount=-amount,
                    description=f"Bank transfer to {recipient_number} ({network_or_bank})",
                    transaction_type='bank_transfer',
                    status='completed'
                )
                db.session.add(transaction)
                db.session.commit()
                
                flash(f'Successfully sent {amount:.2f} TZS to bank account', 'success')
            
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Transfer failed: {str(e)}', 'danger')
            return redirect(url_for('send_money'))
    
    # GET request - show form
    payment_methods = PaymentMethod.query.filter_by(user_id=current_user.id).all()
    total_balance = sum(m.balance for m in payment_methods)
    return render_template('send_money.html', total_balance=total_balance)

def deduct_from_wallet(user_id, amount):
    """Deduct amount from user's wallet (spread across payment methods)"""
    payment_methods = PaymentMethod.query.filter_by(user_id=user_id).order_by(PaymentMethod.balance.desc()).all()
    
    remaining = amount
    for method in payment_methods:
        if remaining <= 0:
            break
        deduct = min(method.balance, remaining)
        method.balance -= deduct
        remaining -= deduct
        db.session.add(method)
    
    if remaining > 0:
        raise ValueError("Insufficient balance")

@app.route('/buy_airtime', methods=['GET', 'POST'])
@login_required
def buy_airtime():
    # Get only mobile payment methods for current user
    payment_methods = PaymentMethod.query.filter_by(
        user_id=current_user.id,
        method_type='mobile'
    ).all()

    if request.method == 'POST':
        try:
            # Get form data
            phone_number = request.form.get('phone_number').strip()
            amount = float(request.form.get('amount'))
            payment_method_id = request.form.get('payment_method_id')
            reference = request.form.get('reference', '').strip()

            # Validate inputs
            if not all([phone_number, amount, payment_method_id]):
                flash('All required fields must be filled', 'danger')
                return redirect(url_for('buy_airtime'))

            # Validate phone number (Tanzanian format)
            if len(phone_number) != 9 or not phone_number.isdigit():
                flash('Invalid phone number format. Use 9 digits without +255', 'danger')
                return redirect(url_for('buy_airtime'))

            # Get payment method
            payment_method = PaymentMethod.query.filter_by(
                id=payment_method_id,
                user_id=current_user.id
            ).first_or_404()

            # Clean sender number for comparison
            sender_number = payment_method.account_number.replace('+255', '').strip()
            
            # Prevent self-transfer
            if phone_number == sender_number:
                flash('You cannot send money to your own number', 'danger')
                return redirect(url_for('buy_airtime'))

            # Validate amount
            if amount < 100 or amount > 1000000:
                flash('Amount must be between 100 and 1,000,000 TZS', 'danger')
                return redirect(url_for('buy_airtime'))

            # Check sufficient balance (including potential fees)
            required_amount = amount * 1.01  # Example: 1% fee
            if payment_method.balance < required_amount:
                flash(f'Insufficient balance. You need {required_amount:.2f} TZS for this transaction', 'danger')
                return redirect(url_for('buy_airtime'))

            # Process transaction
            db.session.begin()
            try:
                # Deduct from sender (amount + fee)
                payment_method.balance -= required_amount
                db.session.add(payment_method)

                # Record transaction
                new_transaction = Transaction(
                    user_id=current_user.id,
                    payment_method_id=payment_method_id,
                    amount=amount,
                    fee=required_amount - amount,
                    description=f"Airtime purchase for {phone_number}",
                    status='completed',
                    transaction_type='airtime_purchase',
                    quantum_id=f"AIR-{datetime.utcnow().timestamp()}",
                    reference=reference,
                    metadata={
                        'recipient_phone': phone_number,
                        'sender_account': payment_method.account_number,
                        'network': detect_network(phone_number),
                        'reference': reference
                    }
                )
                db.session.add(new_transaction)

                # Update user's total balance
                current_user.update_balances()
                
                db.session.commit()

                flash(f'Successfully purchased {amount:.2f} TZS airtime for {phone_number}', 'success')
                return redirect(url_for('transactions'))

            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Airtime purchase failed: {str(e)}', exc_info=True)
                flash('Transaction failed. Please try again.', 'danger')
                return redirect(url_for('buy_airtime'))

        except ValueError:
            flash('Invalid amount entered', 'danger')
            return redirect(url_for('buy_airtime'))
        except Exception as e:
            flash('An error occurred processing your request', 'danger')
            app.logger.error(f'Unexpected error in buy_airtime: {str(e)}', exc_info=True)
            return redirect(url_for('buy_airtime'))

    # GET request - show form
    return render_template('buy_airtime.html', 
                        payment_methods=payment_methods,
                        current_balance=getattr(current_user, 'total_balance', 0))


@app.route('/pay_bills', methods=['GET', 'POST'])
@login_required
def pay_bills():
    # Get user's payment methods and wallet balance
    payment_methods = PaymentMethod.query.filter_by(
        user_id=current_user.id
    ).all()
    
    wallet_balance = float(current_user.wallet_balance) if current_user.wallet_balance is not None else 0.00
    total_balance = wallet_balance + sum(pm.balance for pm in payment_methods)

    if request.method == 'POST':
        try:
            # Get and validate form data
            service = request.form.get('service', '').strip()
            account_number = request.form.get('account_number', '').strip()
            amount = float(request.form.get('amount', 0))
            payment_method_id = request.form.get('payment_method')
            reference = request.form.get('reference', '').strip()

            # Validate inputs
            if not all([service, account_number, amount, payment_method_id]):
                flash('All required fields must be filled', 'danger')
                return redirect(url_for('pay_bills'))

            if amount < 100 or amount > 1000000:
                flash('Amount must be between 100 and 1,000,000 TZS', 'danger')
                return redirect(url_for('pay_bills'))

            # Process payment based on method
            db.session.begin()
            try:
                if payment_method_id == 'wallet':
                    # Wallet payment
                    if wallet_balance < amount:
                        flash('Insufficient wallet balance', 'danger')
                        return redirect(url_for('pay_bills'))
                    
                    current_user.wallet_balance -= amount
                    payment_source = 'PayMe Wallet'
                else:
                    # Payment method payment
                    method = PaymentMethod.query.filter_by(
                        id=payment_method_id,
                        user_id=current_user.id
                    ).first_or_404()

                    if method.balance < amount:
                        flash('Insufficient balance in selected account', 'danger')
                        return redirect(url_for('pay_bills'))
                    
                    method.balance -= amount
                    db.session.add(method)
                    payment_source = f"{method.provider} - {method.account_number}"

                # Record transaction
                transaction = Transaction(
                    user_id=current_user.id,
                    amount=amount,
                    description=f"Bill payment to {service}",
                    status='completed',
                    transaction_type='bill_payment',
                    reference=reference,
                    metadata={
                        'service': service,
                        'account_number': account_number,
                        'payment_source': payment_source,
                        'reference': reference
                    }
                )
                db.session.add(transaction)

                # Update user's total balance
                current_user.total_balance = wallet_balance + sum(pm.balance for pm in payment_methods)
                db.session.add(current_user)

                db.session.commit()

                flash(f'Successfully paid {amount:.2f} TZS to {service}', 'success')
                return redirect(url_for('transactions'))

            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Bill payment failed: {str(e)}', exc_info=True)
                flash('Payment failed. Please try again.', 'danger')
                return redirect(url_for('pay_bills'))

        except ValueError:
            flash('Invalid amount entered', 'danger')
            return redirect(url_for('pay_bills'))
        except Exception as e:
            app.logger.error(f'Unexpected error in pay_bills: {str(e)}', exc_info=True)
            flash('An error occurred processing your request', 'danger')
            return redirect(url_for('pay_bills'))

    # GET request - show form
    return render_template('pay_bills.html',
                         payment_methods=payment_methods,
                         wallet_balance=wallet_balance,
                         total_balance=total_balance)
    
    # GET request - show form
    payment_methods = PaymentMethod.query.filter_by(
        user_id=current_user.id
    ).all()
    
    return render_template('pay_bills.html',
                         payment_methods=payment_methods,
                         wallet_balance=wallet_balance)


@app.route('/play_and_win')
def play_and_win():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('play_and_win.html')

@app.route('/payment_methods', methods=['GET', 'POST'])
@login_required
def payment_methods():
    if request.method == 'POST':
        try:
            # Required fields validation
            required_fields = {
                'method_type': str,
                'account_number': str
            }
            
            for field, field_type in required_fields.items():
                if field not in request.form or not isinstance(request.form[field], field_type):
                    flash(f"Missing or invalid {field.replace('_', ' ')}", "danger")
                    return redirect(url_for('payment_methods'))

            method_type = request.form['method_type'].lower()
            account_number = request.form['account_number'].strip()
            account_name = request.form.get('account_name', '').strip()

            # Provider detection
            provider = None
            if method_type == 'mobile':
                if not (account_number.startswith('+255') and len(account_number) == 13):
                    flash("Tanzanian mobile numbers must start with +255 and be 13 digits", "danger")
                    return redirect(url_for('payment_methods'))
                
                    provider = detect_network(account_number)  # Reuse the existing detect_network function
            
            elif method_type == 'bank':
                if not (account_number.isdigit() and len(account_number) >= 10):
                    flash("Bank accounts must be at least 10 digits", "danger")
                    return redirect(url_for('payment_methods'))
                
                provider = request.form.get('bank_name', 'Unknown Bank')
            
            else:
                flash("Invalid payment method type", "danger")
                return redirect(url_for('payment_methods'))

            # Check for duplicate account
            if PaymentMethod.query.filter_by(
                user_id=current_user.id,
                account_number=account_number
            ).first():
                flash("This account is already registered", "danger")
                return redirect(url_for('payment_methods'))

            # Create payment method
            new_method = PaymentMethod(
                user_id=current_user.id,
                method_type=method_type,
                provider=provider,
                account_number=account_number,
                account_name=account_name or current_user.username,
                balance=0.00,
                is_default=False
            )

            db.session.add(new_method)
            db.session.commit()
            flash("Payment method added successfully!", "success")

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Payment method error: {str(e)}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", "danger")

        return redirect(url_for('payment_methods'))

    # GET request - show form
    return render_template('payment_methods.html',
                         banks=['CRDB', 'NMB', 'Stanbic', 'Equity'])

@app.route('/remove-payment-method', methods=['POST'])
@login_required
def remove_payment_method():
    if request.method == 'POST':
        try:
            data = request.get_json()
            method_id = data.get('method_id')
            
            if not method_id:
                return jsonify({'success': False, 'message': 'Method ID is required'}), 400
            
            # Verify the payment method belongs to current user
            payment_method = PaymentMethod.query.filter_by(
                id=method_id,
                user_id=current_user.id
            ).first()
            
            if not payment_method:
                return jsonify({'success': False, 'message': 'Payment method not found'}), 404
                
            # Check if this is the default method
            if payment_method.is_default:
                return jsonify({'success': False, 'message': 'Cannot remove default payment method'}), 400
            
            # Delete the payment method
            db.session.delete(payment_method)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Payment method removed successfully'
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'message': f'Error removing payment method: {str(e)}'
            }), 500

@app.route('/otp_verification')
def otp_verification():
    phone = request.args.get('phone')
    return render_template('otp_verification.html', phone=phone)

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    # This endpoint should primarily be used via AJAX
    is_ajax = request.headers.get('Accept') == 'application/json'
    if not is_ajax:
        return "This action requires JavaScript.", 405 # Method Not Allowed (or redirect)

    try:
        data = request.get_json()
        if not data or 'phone' not in data:
             return jsonify({'error': 'Phone number is required.'}), 400

        phone = data['phone'].strip()

        # Basic validation of phone format on backend too
        if not phone or not phone.startswith('+255') or len(phone) != 13 or not phone[1:].isdigit():
            return jsonify({'error': 'Invalid phone number format provided.'}), 400

        # Optional: Rate limiting check (e.g., Redis, DB timestamp check)
        # Implement based on your requirements to prevent abuse

        # Generate new OTP and expiry
        otp_code = generate_otp()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

        # Store new OTP record (Corrected)
        otp_record = OTPVerification(
            phone=phone,
            otp_code=otp_code,
            expires_at=expires_at # **FIXED**
        )
        db.session.add(otp_record)
        db.session.commit()

        # Send OTP via SMS
        sms_sent = send_otp_via_sms(phone, otp_code)

        if sms_sent:
             logger.info(f"Resent OTP successfully to {phone}")
             return jsonify({'success': True, 'message': 'New verification code sent successfully.'}), 200
        else:
            logger.error(f"Failed to resend OTP SMS to {phone}")
            # Don't reveal too much detail, but indicate failure
            return jsonify({'error': 'Failed to send new code. Please try again shortly.'}), 500

    except Exception as e:
        db.session.rollback()
        logger.error(f"Resend OTP error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An error occurred while resending the code.'}), 500

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    # This endpoint assumes AJAX request
    is_ajax = request.headers.get('Accept') == 'application/json'
    if not is_ajax:
        return "This action requires JavaScript.", 405

    try:
        data = request.get_json()
        phone = data.get('phone')
        otp_code = data.get('otp_code')

        if not phone or not otp_code:
            return jsonify({'error': 'Phone number and OTP code are required.'}), 400

        # Find the most recent, unverified, unexpired OTP
        otp_record = OTPVerification.query.filter(
            OTPVerification.phone == phone,
            OTPVerification.verified == False,
            OTPVerification.expires_at > datetime.now(timezone.utc)
        ).order_by(OTPVerification.created_at.desc()).first()

        if not otp_record:
            return jsonify({'error': 'Invalid or expired OTP code. Please request a new one.'}), 400 # 400 Bad Request

        if otp_record.otp_code != otp_code:
            otp_record.attempts += 1
            db.session.add(otp_record)
            db.session.commit() # Commit attempt count
            return jsonify({'error': 'Incorrect OTP code entered.'}), 400 # 400 Bad Request

        # --- OTP is Correct ---
        otp_record.verified = True
        db.session.add(otp_record)
        db.session.commit()
        logger.info(f"Standalone OTP verified successfully for {phone}")

        return jsonify({'success': True, 'message': 'OTP verified successfully.'}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Verify OTP error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An error occurred during OTP verification.'}), 500

@app.route('/transactions')
@login_required
def transactions():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    transactions = Transaction.query.filter(
        (Transaction.user_id == current_user.id) |
        (Transaction.sender_id == current_user.id) |
        (Transaction.recipient_id == current_user.id)
    ).order_by(
        Transaction.timestamp.desc()
    ).paginate(page=page, per_page=per_page)

    return jsonify({
        'transactions': [{
            'id': tx.id,
            'reference': tx.reference,
            'amount': tx.amount,
            'type': tx.transaction_type,
            'status': tx.status,
            'timestamp': tx.timestamp.isoformat(),
            'description': tx.description,
            'sender': tx.sender.username if tx.sender else None,
            'recipient': tx.recipient.username if tx.recipient else None,
            'balance_after': tx.sender_balance_after if tx.sender_id == current_user.id else tx.recipient_balance_after
        } for tx in transactions.items],
        'total': transactions.total,
        'pages': transactions.pages,
        'current_page': transactions.page
    })

@app.route('/transactions/<int:transaction_id>')
@login_required
def view_transaction(transaction_id):
    transaction = Transaction.query.filter_by(
        id=transaction_id,
        user_id=current_user.id
    ).first_or_404()
    
    # Format the amount with proper sign
    formatted_amount = "{:,.2f}".format(abs(transaction.amount))
    if transaction.amount > 0:
        amount_display = f"+ {formatted_amount}"
        amount_class = "credit"
    else:
        amount_display = f"- {formatted_amount}"
        amount_class = "debit"
    
    return render_template(
        'transaction_receipt.html',
        transaction=transaction,
        user=current_user,
        amount_display=amount_display,
        amount_class=amount_class,
        formatted_time=transaction.timestamp.strftime("%d %b %Y at %H:%M")
    )

from flask import request, render_template, redirect, url_for, flash
from forex_python.converter import CurrencyRates

from forex_python.converter import CurrencyRates

@app.route('/currency_dashboard')
@login_required
def currency_dashboard():
    # Get current balances
    wallet_balance_tzs = current_user.wallet_balance  # Assuming this is in TZS
    c = CurrencyRates()
    
    try:
        # Get current exchange rate
        usd_rate = c.get_rate('TZS', 'USD')
        wallet_balance_usd = round(wallet_balance_tzs * usd_rate, 2)
        
        # Get conversion history
        history = CurrencyConversion.query.filter_by(
            user_id=current_user.id
        ).order_by(CurrencyConversion.timestamp.desc()).limit(5).all()
        
        return render_template('currency_dashboard.html',
                            wallet_balance_tzs=wallet_balance_tzs,
                            wallet_balance_usd=wallet_balance_usd,
                            usd_rate=usd_rate,
                            history=history)
    
    except Exception as e:
        flash(f'Could not fetch exchange rates: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/convert_currency', methods=['POST'])
@login_required
def convert_currency():
    try:
        amount_tzs = float(request.form.get('amount'))
        c = CurrencyRates()
        usd_rate = c.get_rate('TZS', 'USD')
        amount_usd = round(amount_tzs * usd_rate, 2)
        
        # Deduct from user's balance (assuming wallet is in TZS)
        if current_user.wallet_balance < amount_tzs:
            flash('Insufficient balance', 'danger')
            return redirect(url_for('currency_dashboard'))
        
        current_user.wallet_balance -= amount_tzs
        db.session.add(current_user)
        
        # Record the conversion
        conversion = CurrencyConversion(
            user_id=current_user.id,
            amount_tzs=amount_tzs,
            amount_usd=amount_usd,
            rate=usd_rate
        )
        db.session.add(conversion)
        db.session.commit()
        
        flash(f'Successfully converted {amount_tzs:,.2f} TZS to {amount_usd:,.2f} USD', 'success')
        return redirect(url_for('currency_dashboard'))
    
    except Exception as e:
        db.session.rollback()
        flash(f'Conversion failed: {str(e)}', 'danger')
        return redirect(url_for('currency_dashboard'))


@app.route('/support')
def support():
    # Sample FAQ data - you can replace this with database queries
    faqs = [
        {
            'question': 'How do I create an account?',
            'answer': 'Click on the Register button in the top navigation and follow the instructions to create your PayMe account.'
        },
        {
            'question': 'How do I reset my password?',
            'answer': 'Go to the login page and click "Forgot Password". You\'ll receive instructions to reset your password via email.'
        },
        {
            'question': 'What payment methods are supported?',
            'answer': 'We support mobile money (M-Pesa, Tigo Pesa, Airtel Money) and bank transfers from all major Tanzanian banks.'
        },
        {
            'question': 'Are there any transaction fees?',
            'answer': 'Transactions under 50,000 TZS are free. Above that amount, a small fee of 500 TZS applies.'
        },
        {
            'question': 'How long do transfers take?',
            'answer': 'Most transfers are instant. In rare cases, it may take up to 24 hours for bank transfers.'
        }
    ]

    support_contacts = [
        {'method': 'Phone', 'details': '+255 123 456 789', 'icon': 'fa-phone'},
        {'method': 'Email', 'details': 'support@payme.co.tz', 'icon': 'fa-envelope'},
        {'method': 'Live Chat', 'details': 'Available 24/7 in app', 'icon': 'fa-comments'},
        {'method': 'Twitter', 'details': '@PayMeSupport', 'icon': 'fa-twitter'},
        {'method': 'Office', 'details': '123 Finance Street, Dar es Salaam', 'icon': 'fa-building'}
    ]

    return render_template('support.html', 
                         faqs=faqs, 
                         support_contacts=support_contacts,
                         title='Support Center')

@app.route('/about')
def about():
    team_members = [
        {"name": "John Doe", "role": "Founder & CEO", "bio": "10+ years in fintech", "avatar": "john.jpg"},
        {"name": "Jane Smith", "role": "CTO", "bio": "Blockchain expert", "avatar": "jane.jpg"},
        {"name": "David Johnson", "role": "Lead Developer", "bio": "Payment systems specialist", "avatar": "david.jpg"}
    ]
    
    stats = {
        "users": 250000,
        "transactions": 5000000,
        "years": 5
    }
    
    return render_template('about.html', 
                         team_members=team_members,
                         stats=stats)

@app.route('/profile')
@login_required
def profile():
    # Get user's recent transactions (last 5)
    transactions = Transaction.query.filter_by(
        user_id=current_user.id
    ).order_by(Transaction.timestamp.desc()).limit(5).all()
    
    # Get user's payment methods
    payment_methods = PaymentMethod.query.filter_by(
        user_id=current_user.id
    ).all()
    
    return render_template('profile.html',
                         user=current_user,
                         transactions=transactions,
                         payment_methods=payment_methods)


@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    try:
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        
        # Basic validation
        if not all([username, email, phone]):
            flash('All fields are required', 'danger')
            return redirect(url_for('profile'))
        
        # Update user profile
        current_user.username = username
        current_user.email = email
        current_user.phone = phone
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating profile: {str(e)}', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', user=current_user)

@app.route('/settings/update_password', methods=['POST'])
@login_required
def update_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not all([current_password, new_password, confirm_password]):
        flash('All fields are required', 'danger')
        return redirect(url_for('settings'))
    
    if not check_password_hash(current_user.password, current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('settings'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('settings'))
    
    try:
        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Password updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating password: {str(e)}', 'danger')
    
    return redirect(url_for('settings'))

@app.route('/update_preferences', methods=['POST'])
@login_required
def update_preferences():
    try:
        theme = request.form.get('theme', 'light')
        current_user.theme = theme
        db.session.commit()
        
        # Update other preferences as needed
        current_user.language = request.form.get('language', 'en')
        current_user.currency = request.form.get('currency', 'TZS')
        
        db.session.commit()
        flash('Preferences updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating preferences', 'danger')
    
    return redirect(url_for('settings'))

@app.route('/settings/update_notifications', methods=['POST'])
@login_required
def update_notifications():
    email_notifications = request.form.get('email_notifications') == 'on'
    sms_notifications = request.form.get('sms_notifications') == 'on'
    
    try:
        current_user.email_notifications = email_notifications
        current_user.sms_notifications = sms_notifications
        db.session.commit()
        flash('Notification preferences updated!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating preferences: {str(e)}', 'danger')
    
    return redirect(url_for('settings'))

@app.route('/deactivate_account', methods=['POST'])
@login_required
def deactivate_account():
    password = request.form.get('password')
    
    if not check_password_hash(current_user.password, password):
        flash('Incorrect password', 'danger')
        return redirect(url_for('settings'))
    
    try:
        current_user.active = False
        db.session.commit()
        logout_user()
        flash('Your account has been deactivated', 'info')
        return redirect(url_for('login'))
    except Exception as e:
        db.session.rollback()
        flash('Error deactivating account', 'danger')
        return redirect(url_for('settings'))


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    try:
        # Debug: Print the form data received
        print("Form data:", request.form)
        
        password = request.form.get('password')
        
        # Debug: Print the password received
        print("Password received:", password)
        
        if not password:
            flash("Password is required", "danger")
            return redirect(url_for('settings'))

        if not current_user.check_password(password):
            flash("Incorrect password", "danger")
            return redirect(url_for('settings'))

        # Debug: Print user info before deletion
        print(f"Deleting user: {current_user.username} (ID: {current_user.id})")
        
        # Delete dependent records first
        Transaction.query.filter_by(user_id=current_user.id).delete()
        PaymentMethod.query.filter_by(user_id=current_user.id).delete()
        ChatMessage.query.filter_by(user_id=current_user.id).delete()
        
        # Debug: Count records to be deleted
        print(f"Deleting {Transaction.query.filter_by(user_id=current_user.id).count()} transactions")
        print(f"Deleting {PaymentMethod.query.filter_by(user_id=current_user.id).count()} payment methods")
        print(f"Deleting {ChatMessage.query.filter_by(user_id=current_user.id).count()} chat messages")
        
        # Store username for flash message before deletion
        username = current_user.username
        
        # Delete the user
        db.session.delete(current_user)
        db.session.commit()
        
        # Debug: Print confirmation
        print(f"User {username} deleted successfully")
        
        logout_user()
        flash(f"Account {username} deleted successfully.", "success")
        return redirect(url_for('index'))
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting account: {str(e)}")
        flash(f"Error deleting account: {str(e)}", "danger")
        return redirect(url_for('settings'))

@app.route('/verify', methods=['POST'])
@login_required
def verify_password():
    password = request.form.get('password')
    
    if not hasattr(current_user, 'check_password'):
        return "User model not properly configured", 500
        
    if current_user.check_password(password):
        return "Password correct!"
    else:
        return "Invalid password", 401

@admin_bp.route('/')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    
    stats = {
        'total_users': User.query.count(),
        'total_transactions': Transaction.query.count(),
        'recent_users': User.query.order_by(User.created_at.desc()).limit(5).all()
    }
    return render_template('admin/dashboard.html', stats=stats)

@admin_bp.route('/users')
@admin_required
def manage_users():
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.created_at.desc()).paginate(page=page, per_page=10)
    return render_template('admin/user.html', users=users.items, pagination=users)

@admin_bp.route('/users/create', methods=['GET', 'POST'])
@admin_required
def create_user():
    form = UserForm()  # You'll need to create this form class
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            phone=form.phone.data,
            password=generate_password_hash(form.password.data),
            is_admin=form.is_admin.data
        )
        db.session.add(user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('admin.manage_users'))
    return render_template('admin/create_user.html', form=form)

@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm(obj=user)  # Different form without password field
    if form.validate_on_submit():
        form.populate_obj(user)
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin.manage_users'))
    return render_template('admin/edit_user.html', form=form, user=user)

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Cannot delete admin users!', 'danger')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/transactions')
@login_required
def view_transactions():
    if not current_user.is_admin:
        abort(403)
    
    transactions = Transaction.query.order_by(Transaction.timestamp.desc()).limit(100).all()
    return render_template('admin/transactions.html', transactions=transactions)

@admin_bp.route('/promote/<int:user_id>')
@login_required
def promote_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash(f"{user.username} is now an admin", "success")
    return redirect(url_for('admin.manage_users'))

# Register blueprint in your app
app.register_blueprint(admin_bp)


@app.route('/terms')
def terms():
    return render_template('terms.html', current_date=datetime.now().strftime('%Y-%m-%d'))

@app.route('/privacy')
def privacy():
    return render_template('privacy.html', current_date=datetime.now().strftime('%Y-%m-%d'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

# Initialize database when application starts
init_db()

if __name__ == '__main__':
    init_db()  # Initialize database before first request
    app.run(debug=True)