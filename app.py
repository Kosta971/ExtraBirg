from flask import Flask, render_template_string, request, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import requests, os, uuid, datetime
from functools import wraps
import pickle
import logging  # Добавлено логирование

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24).hex())  # Более безопасная генерация ключа

# Конфигурация БД
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///xtrabirg.db').replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {  # Настройки пула соединений
    'pool_size': 10,
    'pool_recycle': 300,
    'pool_pre_ping': True
}

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', logger=True, engineio_logger=True)

# Конфигурация API
NOWPAYMENTS_API = os.getenv("NOWPAYMENTS_API_KEY")
STRIPE_PUBKEY = os.getenv("STRIPE_PUBKEY", "")
STRIPE_SECRET = os.getenv("STRIPE_SECRET", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", os.urandom(16).hex())  # Безопасный пароль по умолчанию

SUPPORTED_TOKENS = {
    "BTC": "bitcoin",
    "ETH": "ethereum",
    "SOL": "solana",
    "DOGE": "dogecoin",
    "XTRA": "usd"
}

# Модели базы данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)  # Добавлен индекс
    password_hash = db.Column(db.String(256), nullable=False)
    balances = db.Column(db.PickleType, nullable=False, default=pickle.dumps({"USDT": 0.0, "BTC": 0.0, "ETH": 0.0, "SOL": 0.0, "DOGE": 0.0, "XTRA": 0.0}))

    def get_balances(self):
        try:
            return pickle.loads(self.balances) if isinstance(self.balances, bytes) else self.balances
        except Exception as e:
            logger.error(f"Error decoding balances: {e}")
            return {"USDT": 0.0, "BTC": 0.0, "ETH": 0.0, "SOL": 0.0, "DOGE": 0.0, "XTRA": 0.0}

    def set_balances(self, balances):
        try:
            self.balances = pickle.dumps(balances)
        except Exception as e:
            logger.error(f"Error encoding balances: {e}")
            self.balances = pickle.dumps({"USDT": 0.0, "BTC": 0.0, "ETH": 0.0, "SOL": 0.0, "DOGE": 0.0, "XTRA": 0.0})

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False, index=True)  # Добавлен индекс
    type = db.Column(db.String(50), nullable=False)
    token = db.Column(db.String(10), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)  # Добавлен индекс

# Инициализация БД
def initialize_database():
    try:
        with app.app_context():
            db.create_all()
            logger.info("✅ Database tables created successfully!")
    except Exception as e:
        logger.error(f"❌ Database initialization error: {e}")

initialize_database()

# Вспомогательные функции
def get_price(token):
    if token == "XTRA":
        return 1.0
    try:
        name = SUPPORTED_TOKENS.get(token)
        if not name:
            logger.warning(f"Unsupported token: {token}")
            return 0.0
        
        res = requests.get(
            f"https://api.coingecko.com/api/v3/simple/price?ids={name}&vs_currencies=usd",
            timeout=10,
            headers={'User-Agent': 'XtraBirg/1.0'}
        )
        res.raise_for_status()
        return res.json()[name]['usd']
    except requests.exceptions.RequestException as e:
        logger.error(f"Price fetch error for {token}: {e}")
        return 0.0
    except Exception as e:
        logger.error(f"Unexpected error in get_price: {e}")
        return 0.0

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect('/')
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            return redirect('/admin-login')
        return f(*args, **kwargs)
    return decorated

# Маршруты аутентификации
@app.route('/register', methods=['POST'])
def register():
    try:
        email = request.form.get('email', '').strip().lower()  # Нормализация email
        password = request.form.get('password', '').strip()
        
        if len(email) < 5 or '@' not in email:
            return "Invalid email format", 400
        if len(password) < 8:
            return "Password must be at least 8 characters", 400
        
        if User.query.filter_by(email=email).first():
            return "Email already registered", 400
            
        user = User(
            email=email,
            password_hash=generate_password_hash(password),
            balances=pickle.dumps({"USDT": 0.0, "BTC": 0.0, "ETH": 0.0, "SOL": 0.0, "DOGE": 0.0, "XTRA": 0.0})
        )
        
        db.session.add(user)
        db.session.commit()
        session['user'] = email
        return redirect('/')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {e}", exc_info=True)
        return "Registration failed. Please try again.", 500

@app.route('/login', methods=['POST'])
def login():
    try:
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            return "Invalid credentials", 401
            
        session['user'] = email
        return redirect('/')
    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return "Login failed. Please try again.", 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# Маршруты торговли
@app.route('/buy', methods=['POST'])
@require_auth
def buy():
    try:
        token = request.form.get('token')
        amount = float(request.form.get('amount', 0))
        
        if token not in SUPPORTED_TOKENS:
            return "Unsupported token", 400
        if amount <= 0:
            return "Amount must be positive", 400
            
        user = User.query.filter_by(email=session['user']).first()
        if not user:
            return "User not found", 404
            
        price = get_price(token)
        if price <= 0:
            return "Could not fetch valid price", 500
            
        total = amount * price
        
        balances = user.get_balances()
        if balances.get('USDT', 0) < total:
            return "Insufficient USDT balance", 400
            
        # Атомарная операция
        try:
            balances['USDT'] -= total
            balances[token] = balances.get(token, 0) + amount
            user.set_balances(balances)
            
            transaction = Transaction(
                user_email=user.email,
                type="buy",
                token=token,
                amount=amount,
                price=price
            )
            
            db.session.add(transaction)
            db.session.commit()
            return redirect('/')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Transaction error: {e}", exc_info=True)
            return "Transaction failed. Please try again.", 500
            
    except ValueError:
        return "Invalid amount", 400
    except Exception as e:
        logger.error(f"Buy operation error: {e}", exc_info=True)
        return "Operation failed. Please try again.", 500

# Остальные маршруты (deposit, stripe, history и т.д.) должны быть аналогично улучшены
# ...

# Обработка ошибок
@app.errorhandler(404)
def not_found(e):
    return render_template_string('<h1>404 Not Found</h1>'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}", exc_info=True)
    return render_template_string('<h1>500 Internal Server Error</h1>'), 500

if __name__ == '__main__':
    try:
        with app.app_context():
            db.create_all()
        socketio.run(app, 
                    host='0.0.0.0', 
                    port=int(os.getenv('PORT', 5000)), 
                    debug=os.getenv('DEBUG', 'false').lower() == 'true',
                    use_reloader=False)
    except Exception as e:
        logger.critical(f"Application startup failed: {e}", exc_info=True)
