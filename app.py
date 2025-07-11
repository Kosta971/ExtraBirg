from flask import Flask, render_template_string, request, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import requests, os, uuid, datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecret")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///xtrabirg.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Конфигурация API
NOWPAYMENTS_API = os.getenv("NOWPAYMENTS_API_KEY")
STRIPE_PUBKEY = os.getenv("STRIPE_PUBKEY", "")
STRIPE_SECRET = os.getenv("STRIPE_SECRET", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "adminpass")

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
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    balances = db.Column(db.PickleType, default={"USDT": 0.0, "BTC": 0.0, "ETH": 0.0, "SOL": 0.0, "DOGE": 0.0, "XTRA": 0.0})

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    token = db.Column(db.String(10), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)

# Вспомогательные функции
def get_price(token):
    """Получает текущую цену токена"""
    if token == "XTRA":
        return 1.0
    try:
        name = SUPPORTED_TOKENS.get(token)
        if not name:
            return 0.0
        res = requests.get(f"https://api.coingecko.com/api/v3/simple/price?ids={name}&vs_currencies=usd")
        res.raise_for_status()
        return res.json()[name]['usd']
    except Exception as e:
        print(f"Error fetching price for {token}: {e}")
        return 0.0

def require_auth(f):
    """Декоратор для проверки аутентификации"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect('/')
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    """Декоратор для проверки прав администратора"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            return redirect('/admin-login')
        return f(*args, **kwargs)
    return decorated

# Маршруты аутентификации
@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    
    if not email or not password:
        return "Email and password are required", 400
    
    if User.query.filter_by(email=email).first():
        return "Email already registered", 400
        
    try:
        user = User(
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        session['user'] = email
        return redirect('/')
    except Exception as e:
        db.session.rollback()
        return f"Registration failed: {str(e)}", 500

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return "Invalid credentials", 401
        
    session['user'] = email
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('admin', None)
    return redirect('/')

# Маршруты торговли
@app.route('/buy', methods=['POST'])
@require_auth
def buy():
    token = request.form.get('token')
    amount = float(request.form.get('amount', 0))
    
    if token not in SUPPORTED_TOKENS:
        return "Unsupported token", 400
    if amount <= 0:
        return "Amount must be positive", 400
        
    user = User.query.filter_by(email=session['user']).first()
    price = get_price(token)
    total = amount * price
    
    if user.balances.get('USDT', 0) < total:
        return "Insufficient USDT balance", 400
        
    try:
        user.balances['USDT'] -= total
        user.balances[token] = user.balances.get(token, 0) + amount
        
        db.session.add(Transaction(
            user_email=user.email,
            type="buy",
            token=token,
            amount=amount,
            price=price
        ))
        db.session.commit()
        return redirect('/')
    except Exception as e:
        db.session.rollback()
        return f"Transaction failed: {str(e)}", 500

# Маршруты пополнения
@app.route('/deposit', methods=['POST'])
@require_auth
def deposit():
    amount = float(request.form.get('amount', 0))
    if amount <= 0:
        return "Amount must be positive", 400
        
    if not NOWPAYMENTS_API:
        return "NOWPayments service not configured", 503
        
    try:
        payload = {
            "price_amount": amount,
            "price_currency": "usd",
            "pay_currency": "usdttrc20",
            "ipn_callback_url": "https://yourdomain.com/nowpayments-webhook",
            "order_id": str(uuid.uuid4()),
            "order_description": f"Deposit for {session['user']}"
        }
        headers = {"x-api-key": NOWPAYMENTS_API}
        res = requests.post(
            "https://api.nowpayments.io/v1/invoice",
            json=payload,
            headers=headers,
            timeout=10
        )
        res.raise_for_status()
        return redirect(res.json().get("invoice_url", "/"))
    except Exception as e:
        return f"Payment processing failed: {str(e)}", 500

@app.route('/stripe', methods=['POST'])
@require_auth
def stripe():
    amount = float(request.form.get('amount', 0))
    if amount <= 0:
        return "Amount must be positive", 400
        
    if not STRIPE_SECRET:
        return "Stripe service not configured", 503
        
    try:
        amount_cents = int(amount * 100)
        stripe_session = requests.post(
            "https://api.stripe.com/v1/checkout/sessions",
            headers={
                "Authorization": f"Bearer {STRIPE_SECRET}",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            data={
                "payment_method_types[]": "card",
                "line_items[0][price_data][currency]": "usd",
                "line_items[0][price_data][product_data][name]": "USDT Balance Top-up",
                "line_items[0][price_data][unit_amount]": str(amount_cents),
                "line_items[0][quantity]": "1",
                "mode": "payment",
                "success_url": f"{request.host_url}success?amount={amount}",
                "cancel_url": f"{request.host_url}"
            },
            timeout=10
        )
        stripe_session.raise_for_status()
        return redirect(stripe_session.json().get("url", "/"))
    except Exception as e:
        return f"Stripe processing failed: {str(e)}", 500

@app.route('/success')
@require_auth
def stripe_success():
    amount = float(request.args.get("amount", 0))
    if amount <= 0:
        return redirect('/')
        
    user = User.query.filter_by(email=session['user']).first()
    try:
        user.balances['USDT'] += amount
        db.session.add(Transaction(
            user_email=user.email,
            type="deposit",
            token="USDT",
            amount=amount,
            price=1
        ))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        
    return redirect('/')

# Маршруты истории и данных
@app.route('/history')
@require_auth
def history():
    txs = Transaction.query.filter_by(
        user_email=session['user']
    ).order_by(
        Transaction.timestamp.desc()
    ).limit(50).all()
    
    return jsonify([{
        "type": tx.type,
        "token": tx.token,
        "amount": tx.amount,
        "price": tx.price,
        "time": tx.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    } for tx in txs])

# Чат
@socketio.on('message')
def handle_message(data):
    if not isinstance(data, str) or len(data.strip()) == 0:
        return
        
    emit('message', {
        'user': session.get('user', 'Guest'),
        'text': data.strip()[:200],
        'time': datetime.datetime.now().strftime("%H:%M")
    }, broadcast=True)

# Админка
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect('/admin')
        return "Wrong admin password!", 401
    
    return render_template_string('''
    <!DOCTYPE html>
    <html class="dark">
    <head>
        <title>Admin Login — XtraBirg</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-900 text-white flex items-center justify-center h-screen">
        <div class="bg-gray-800 p-8 rounded-xl shadow-lg w-full max-w-md">
            <h1 class="text-2xl font-bold mb-6 text-center">🔒 Admin Login</h1>
            <form method="post" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium mb-1">Password</label>
                    <input type="password" name="password" required 
                           class="w-full p-2 rounded bg-gray-700 border border-gray-600 focus:border-blue-500 focus:outline-none">
                </div>
                <button type="submit" 
                        class="w-full bg-blue-600 hover:bg-blue-700 py-2 px-4 rounded font-medium transition-colors">
                    Login
                </button>
            </form>
        </div>
    </body>
    </html>
    ''')

@app.route('/admin')
@require_admin
def admin_panel():
    users = User.query.order_by(User.id.desc()).limit(100).all()
    return render_template_string('''
    <!DOCTYPE html>
    <html class="dark">
    <head>
        <title>Admin Panel — XtraBirg</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-900 text-white min-h-screen">
        <div class="container mx-auto px-4 py-8">
            <div class="flex justify-between items-center mb-8">
                <h1 class="text-3xl font-bold">👑 Admin Panel</h1>
                <a href="/logout" class="text-red-400 hover:text-red-300 underline">Logout</a>
            </div>
            
            <div class="bg-gray-800 rounded-xl shadow-lg overflow-hidden mb-8">
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-700">
                            <tr>
                                <th class="px-6 py-3 text-left">Email</th>
                                <th class="px-6 py-3 text-left">Balances</th>
                                <th class="px-6 py-3 text-left">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-700">
                            {% for user in users %}
                            <tr class="hover:bg-gray-750">
                                <td class="px-6 py-4">{{ user.email }}</td>
                                <td class="px-6 py-4">
                                    {% for token, amount in user.balances.items() %}
                                    <div class="flex justify-between">
                                        <span>{{ token }}</span>
                                        <span>{{ '%.4f'|format(amount) }}</span>
                                    </div>
                                    {% endfor %}
                                </td>
                                <td class="px-6 py-4">
                                    <button class="text-blue-400 hover:text-blue-300">Edit</button>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''', users=users)

# Основные маршруты
@app.route('/')
def index():
    if 'user' not in session:
        return render_template_string('''
        <!DOCTYPE html>
        <html class="dark">
        <head>
            <title>XtraBirg — Crypto Exchange</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css"/>
        </head>
        <body class="bg-gray-900 text-white flex items-center justify-center min-h-screen">
            <div class="w-full max-w-md px-4">
                <div class="text-center mb-8 animate__animated animate__fadeIn">
                    <h1 class="text-4xl font-bold mb-2 bg-gradient-to-r from-blue-500 to-purple-600 bg-clip-text text-transparent">
                        XtraBirg
                    </h1>
                    <p class="text-gray-400">Modern cryptocurrency exchange</p>
                </div>
                
                <div class="bg-gray-800 rounded-xl shadow-xl overflow-hidden animate__animated animate__fadeInUp">
                    <div class="p-1 bg-gradient-to-r from-blue-500 to-purple-600"></div>
                    
                    <div class="p-6">
                        <ul class="flex border-b border-gray-700 mb-6">
                            <li class="mr-1">
                                <button id="login-tab" class="py-2 px-4 font-medium">Login</button>
                            </li>
                            <li class="mr-1">
                                <button id="register-tab" class="py-2 px-4 text-gray-400 hover:text-white">Register</button>
                            </li>
                        </ul>
                        
                        <form id="login-form" action="/login" method="post" class="space-y-4">
                            <div>
                                <label class="block text-sm font-medium mb-1">Email</label>
                                <input name="email" type="email" required
                                       class="w-full p-3 rounded-lg bg-gray-700 border border-gray-600 focus:border-blue-500 focus:outline-none">
                            </div>
                            <div>
                                <label class="block text-sm font-medium mb-1">Password</label>
                                <input name="password" type="password" required
                                       class="w-full p-3 rounded-lg bg-gray-700 border border-gray-600 focus:border-blue-500 focus:outline-none">
                            </div>
                            <button type="submit"
                                    class="w-full bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 py-3 px-4 rounded-lg font-medium transition-all">
                                Login
                            </button>
                        </form>
                        
                        <form id="register-form" action="/register" method="post" class="space-y-4 hidden">
                            <div>
                                <label class="block text-sm font-medium mb-1">Email</label>
                                <input name="email" type="email" required
                                       class="w-full p-3 rounded-lg bg-gray-700 border border-gray-600 focus:border-blue-500 focus:outline-none">
                            </div>
                            <div>
                                <label class="block text-sm font-medium mb-1">Password</label>
                                <input name="password" type="password" required
                                       class="w-full p-3 rounded-lg bg-gray-700 border border-gray-600 focus:border-blue-500 focus:outline-none">
                            </div>
                            <button type="submit"
                                    class="w-full bg-gradient-to-r from-green-500 to-teal-600 hover:from-green-600 hover:to-teal-700 py-3 px-4 rounded-lg font-medium transition-all">
                                Create Account
                            </button>
                        </form>
                    </div>
                </div>
                
                <div class="mt-6 text-center text-gray-500 text-sm">
                    <p>By continuing, you agree to our Terms of Service</p>
                </div>
            </div>
            
            <script>
                document.getElementById('login-tab').addEventListener('click', () => {
                    document.getElementById('login-form').classList.remove('hidden');
                    document.getElementById('register-form').classList.add('hidden');
                    document.getElementById('login-tab').classList.add('text-white', 'border-b-2', 'border-blue-500');
                    document.getElementById('login-tab').classList.remove('text-gray-400');
                    document.getElementById('register-tab').classList.remove('text-white', 'border-b-2', 'border-blue-500');
                    document.getElementById('register-tab').classList.add('text-gray-400');
                });
                
                document.getElementById('register-tab').addEventListener('click', () => {
                    document.getElementById('register-form').classList.remove('hidden');
                    document.getElementById('login-form').classList.add('hidden');
                    document.getElementById('register-tab').classList.add('text-white', 'border-b-2', 'border-blue-500');
                    document.getElementById('register-tab').classList.remove('text-gray-400');
                    document.getElementById('login-tab').classList.remove('text-white', 'border-b-2', 'border-blue-500');
                    document.getElementById('login-tab').classList.add('text-gray-400');
                });
                
                // Activate login tab by default
                document.getElementById('login-tab').click();
            </script>
        </body>
        </html>
        ''')
    
    user = User.query.filter_by(email=session['user']).first()
    prices = {token: get_price(token) for token in SUPPORTED_TOKENS}
    
    return render_template_string('''
    <!DOCTYPE html>
    <html class="dark">
    <head>
        <title>Dashboard — XtraBirg</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.socket.io/4.3.2/socket.io.min.js"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"/>
    </head>
    <body class="bg-gray-900 text-white">
        <!-- Header -->
        <header class="bg-gray-800 shadow-lg">
            <div class="container mx-auto px-4 py-4 flex justify-between items-center">
                <div class="flex items-center space-x-2">
                    <div class="bg-gradient-to-r from-blue-500 to-purple-600 w-8 h-8 rounded-lg"></div>
                    <h1 class="text-xl font-bold">XtraBirg</h1>
                </div>
                
                <div class="flex items-center space-x-4">
                    <a href="/markets" class="hover:text-blue-400 transition-colors">
                        <i class="fas fa-chart-line mr-1"></i> Markets
                    </a>
                    <div class="relative group">
                        <button class="flex items-center space-x-1 hover:text-blue-400 transition-colors">
                            <i class="fas fa-wallet"></i>
                            <span>Balance: ${{ "%.2f"|format(user.balances.get('USDT', 0) * get_price('USDT')) }}</span>
                        </button>
                    </div>
                    <a href="/logout" class="text-red-400 hover:text-red-300 transition-colors">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </header>
        
        <!-- Main Content -->
        <main class="container mx-auto px-4 py-8">
            <!-- Welcome Section -->
            <section class="mb-8">
                <h2 class="text-2xl font-bold mb-2">Welcome back, {{ user.email.split('@')[0] }}!</h2>
                <p class="text-gray-400">Your portfolio overview</p>
            </section>
            
            <!-- Stats Grid -->
            <section class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <!-- Total Balance Card -->
                <div class="bg-gray-800 rounded-xl p-6 shadow-lg border-l-4 border-blue-500">
                    <h3 class="text-gray-400 mb-1">Total Balance</h3>
                    <p class="text-2xl font-bold">
                        ${{ "%.2f"|format(
                            user.balances.get('USDT', 0) * get_price('USDT') +
                            user.balances.get('BTC', 0) * get_price('BTC') +
                            user.balances.get('ETH', 0) * get_price('ETH') +
                            user.balances.get('SOL', 0) * get_price('SOL') +
                            user.balances.get('DOGE', 0) * get_price('DOGE') +
                            user.balances.get('XTRA', 0) * get_price('XTRA')
                        ) }}
                    </p>
                    <div class="mt-2 text-sm text-gray-400 flex justify-between">
                        <span>24h change</span>
                        <span class="text-green-400">+2.3%</span>
                    </div>
                </div>
                
                <!-- Portfolio Distribution Card -->
                <div class="bg-gray-800 rounded-xl p-6 shadow-lg">
                    <h3 class="text-gray-400 mb-3">Portfolio Distribution</h3>
                    <div class="space-y-2">
                        {% for token in ['USDT', 'BTC', 'ETH', 'SOL', 'DOGE', 'XTRA'] %}
                            {% set balance = user.balances.get(token, 0) %}
                            {% if balance > 0 %}
                            <div>
                                <div class="flex justify-between text-sm mb-1">
                                    <span>{{ token }}</span>
                                    <span>${{ "%.2f"|format(balance * get_price(token)) }}</span>
                                </div>
                                <div class="w-full bg-gray-700 rounded-full h-2">
                                    <div class="bg-blue-500 h-2 rounded-full" 
                                         style="width: {{ (balance * get_price(token)) / (
                                             user.balances.get('USDT', 0) * get_price('USDT') +
                                             user.balances.get('BTC', 0) * get_price('BTC') +
                                             user.balances.get('ETH', 0) * get_price('ETH') +
                                             user.balances.get('SOL', 0) * get_price('SOL') +
                                             user.balances.get('DOGE', 0) * get_price('DOGE') +
                                             user.balances.get('XTRA', 0) * get_price('XTRA')
                                         ) * 100 }}%"></div>
                                </div>
                            </div>
                            {% endif %}
                        {% endfor %}
                    </div>
                </div>
                
                <!-- Quick Actions Card -->
                <div class="bg-gray-800 rounded-xl p-6 shadow-lg">
                    <h3 class="text-gray-400 mb-3">Quick Actions</h3>
                    <div class="grid grid-cols-2 gap-3">
                        <a href="#deposit" class="bg-blue-600 hover:bg-blue-700 rounded-lg p-3 text-center transition-colors">
                            <i class="fas fa-plus-circle mb-1"></i>
                            <p>Deposit</p>
                        </a>
                        <a href="#withdraw" class="bg-gray-700 hover:bg-gray-600 rounded-lg p-3 text-center transition-colors">
                            <i class="fas fa-minus-circle mb-1"></i>
                            <p>Withdraw</p>
                        </a>
                        <a href="#buy" class="bg-green-600 hover:bg-green-700 rounded-lg p-3 text-center transition-colors">
                            <i class="fas fa-arrow-up mb-1"></i>
                            <p>Buy</p>
                        </a>
                        <a href="#sell" class="bg-red-600 hover:bg-red-700 rounded-lg p-3 text-center transition-colors">
                            <i class="fas fa-arrow-down mb-1"></i>
                            <p>Sell</p>
                        </a>
                    </div>
                </div>
            </section>
            
            <!-- Trading Section -->
            <section class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                <!-- Buy/Sell Form -->
                <div class="bg-gray-800 rounded-xl p-6 shadow-lg lg:col-span-1">
                    <ul class="flex border-b border-gray-700 mb-6">
                        <li class="mr-1">
                            <button id="buy-tab" class="py-2 px-4 font-medium border-b-2 border-blue-500">Buy</button>
                        </li>
                        <li class="mr-1">
                            <button id="sell-tab" class="py-2 px-4 text-gray-400 hover:text-white">Sell</button>
                        </li>
                    </ul>
                    
                    <form id="buy-form" action="/buy" method="post" class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium mb-1">Token</label>
                            <select name="token" class="w-full p-3 rounded-lg bg-gray-700 border border-gray-600 focus:border-blue-500 focus:outline-none">
                                {% for token in SUPPORTED_TOKENS.keys() %}
                                    <option value="{{ token }}">{{ token }}</option>
                                {% endfor %}
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium mb-1">Amount</label>
                            <input name="amount" type="number" step="0.0001" min="0" required
                                   class="w-full p-3 rounded-lg bg-gray-700 border border-gray-600 focus:border-blue-500 focus:outline-none">
                        </div>
                        <div class="pt-2">
                            <div class="flex justify-between text-sm text-gray-400 mb-1">
                                <span>Price</span>
                                <span id="token-price">$0.00</span>
                            </div>
                            <div class="flex justify-between text-sm text-gray-400 mb-1">
                                <span>Total</span>
                                <span id="buy-total">$0.00</span>
                            </div>
                            <div class="flex justify-between text-sm text-gray-400">
                                <span>Balance</span>
                                <span>${{ "%.2f"|format(user.balances.get('USDT', 0) * get_price('USDT')) }}</span>
                            </div>
                        </div>
                        <button type="submit"
                                class="w-full bg-blue-600 hover:bg-blue-700 py-3 px-4 rounded-lg font-medium transition-colors">
                            Buy
                        </button>
                    </form>
                    
                    <form id="sell-form" action="/sell" method="post" class="space-y-4 hidden">
                        <div>
                            <label class="block text-sm font-medium mb-1">Token</label>
                            <select name="token" class="w-full p-3 rounded-lg bg-gray-700 border border-gray-600 focus:border-blue-500 focus:outline-none">
                                {% for token in SUPPORTED_TOKENS.keys() %}
                                    {% if user.balances.get(token, 0) > 0 %}
                                        <option value="{{ token }}">{{ token }}</option>
                                    {% endif %}
                                {% endfor %}
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium mb-1">Amount</label>
                            <input name="amount" type="number" step="0.0001" min="0" required
                                   class="w-full p-3 rounded-lg bg-gray-700 border border-gray-600 focus:border-blue-500 focus:outline-none">
                        </div>
                        <div class="pt-2">
                            <div class="flex justify-between text-sm text-gray-400 mb-1">
                                <span>Price</span>
                                <span id="sell-token-price">$0.00</span>
                            </div>
                            <div class="flex justify-between text-sm text-gray-400 mb-1">
                                <span>Total</span>
                                <span id="sell-total">$0.00</span>
                            </div>
                            <div class="flex justify-between text-sm text-gray-400">
                                <span>Balance</span>
                                <span id="token-balance">0 {{ token }}</span>
                            </div>
                        </div>
                        <button type="submit"
                                class="w-full bg-red-600 hover:bg-red-700 py-3 px-4 rounded-lg font-medium transition-colors">
                            Sell
                        </button>
                    </form>
                </div>
                
                <!-- Price Charts -->
                <div class="bg-gray-800 rounded-xl p-6 shadow-lg lg:col-span-2">
                    <h3 class="text-gray-400 mb-4">Market Overview</h3>
                    <div class="grid grid-cols-2 md:grid-cols-3 gap-4 mb-6">
                        {% for token, price in prices.items() %}
                        <div class="bg-gray-750 rounded-lg p-3 hover:bg-gray-700 transition-colors cursor-pointer">
                            <div class="flex justify-between items-start">
                                <div>
                                    <p class="font-medium">{{ token}}</p>
                                    <p class="text-gray-400 text-sm">${{ "%.4f"|format(price) }}</p>
                                </div>
                                <div class="text-green-400 text-sm">+{{ range(0.1, 5.0)|random|round(2) }}%</div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                    
                    <div class="h-64 bg-gray-750 rounded-lg flex items-center justify-center">
                        <p class="text-gray-500">Price chart will be displayed here</p>
                    </div>
                </div>
            </section>
            
            <!-- Deposit Section -->
            <section id="deposit" class="bg-gray-800 rounded-xl p-6 shadow-lg mb-8">
                <h3 class="text-gray-400 mb-4">💵 Deposit Funds</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <!-- Crypto Deposit -->
                    <form action="/deposit" method="post" class="space-y-4">
                        <h4 class="font-medium">Crypto Deposit (NOWPayments)</h4>
                        <div>
                            <label class="block text-sm font-medium mb-1">USD Amount</label>
                            <input name="amount" type="number" step="0.01" min="10" required
                                   class="w-full p-3 rounded-lg bg-gray-700 border border-gray-600 focus:border-blue-500 focus:outline-none">
                        </div>
                        <button type="submit"
                                class="w-full bg-purple-600 hover:bg-purple-700 py-3 px-4 rounded-lg font-medium transition-colors">
                            Generate Deposit Address
                        </button>
                    </form>
                    
                    <!-- Card Deposit -->
                    <form action="/stripe" method="post" class="space-y-4">
                        <h4 class="font-medium">Card Payment (Stripe)</h4>
                        <div>
                            <label class="block text-sm font-medium mb-1">USD Amount</label>
                            <input name="amount" type="number" step="0.01" min="5" required
                                   class="w-full p-3 rounded-lg bg-gray-700 border border-gray-600 focus:border-blue-500 focus:outline-none">
                        </div>
                        <button type="submit"
                                class="w-full bg-yellow-600 hover:bg-yellow-700 py-3 px-4 rounded-lg font-medium transition-colors">
                            Pay with Card
                        </button>
                    </form>
                </div>
            </section>
            
            <!-- History & Chat Section -->
            <section class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <!-- Transaction History -->
                <div class="bg-gray-800 rounded-xl p-6 shadow-lg">
                    <h3 class="text-gray-400 mb-4">📜 Transaction History</h3>
                    <div class="overflow-y-auto max-h-80">
                        <table class="w-full">
                            <thead class="text-left text-gray-400 border-b border-gray-700">
                                <tr>
                                    <th class="pb-2">Type</th>
                                    <th class="pb-2">Amount</th>
                                    <th class="pb-2">Price</th>
                                    <th class="pb-2">Time</th>
                                </tr>
                            </thead>
                            <tbody id="history-table">
                                <!-- History will be loaded via JavaScript -->
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <!-- Community Chat -->
                <div class="bg-gray-800 rounded-xl p-6 shadow-lg">
                    <h3 class="text-gray-400 mb-4">💬 Community Chat</h3>
                    <div id="chat-messages" class="h-48 overflow-y-auto mb-4 bg-gray-750 rounded-lg p-3 space-y-2">
                        <!-- Messages will appear here -->
                    </div>
                    <form id="chat-form" class="flex">
                        <input id="chat-input" type="text" placeholder="Type your message..."
                               class="flex-grow p-3 rounded-l-lg bg-gray-700 border border-gray-600 focus:border-blue-500 focus:outline-none">
                        <button type="submit"
                                class="bg-blue-600 hover:bg-blue-700 px-4 rounded-r-lg transition-colors">
                            <i class="fas fa-paper-plane"></i>
                        </button>
                    </form>
                </div>
            </section>
        </main>
        
        <script>
            // Tab switching for buy/sell forms
            document.getElementById('buy-tab').addEventListener('click', () => {
                document.getElementById('buy-form').classList.remove('hidden');
                document.getElementById('sell-form').classList.add('hidden');
                document.getElementById('buy-tab').classList.add('border-blue-500', 'text-white');
                document.getElementById('buy-tab').classList.remove('text-gray-400');
                document.getElementById('sell-tab').classList.remove('border-blue-500', 'text-white');
                document.getElementById('sell-tab').classList.add('text-gray-400');
            });
            
            document.getElementById('sell-tab').addEventListener('click', () => {
                document.getElementById('sell-form').classList.remove('hidden');
                document.getElementById('buy-form').classList.add('hidden');
                document.getElementById('sell-tab').classList.add('border-blue-500', 'text-white');
                document.getElementById('sell-tab').classList.remove('text-gray-400');
                document.getElementById('buy-tab').classList.remove('border-blue-500', 'text-white');
                document.getElementById('buy-tab').classList.add('text-gray-400');
            });
            
            // Price calculation for buy form
            const tokenSelect = document.querySelector('#buy-form select[name="token"]');
            const amountInput = document.querySelector('#buy-form input[name="amount"]');
            
            function updateBuyPrice() {
                const token = tokenSelect.value;
                const amount = parseFloat(amountInput.value) || 0;
                fetch('/get-price?token=' + token)
                    .then(response => response.json())
                    .then(data => {
                        const price = data.price;
                        document.getElementById('token-price').textContent = '$' + price.toFixed(4);
                        document.getElementById('buy-total').textContent = '$' + (price * amount).toFixed(2);
                    });
            }
            
            tokenSelect.addEventListener('change', updateBuyPrice);
            amountInput.addEventListener('input', updateBuyPrice);
            
            // Initialize prices
            updateBuyPrice();
            
            // Load transaction history
            fetch('/history')
                .then(response => response.json())
                .then(data => {
                    const table = document.getElementById('history-table');
                    data.forEach(tx => {
                        const row = document.createElement('tr');
                        row.className = 'border-b border-gray-750 hover:bg-gray-750';
                        row.innerHTML = `
                            <td class="py-3 ${tx.type === 'buy' ? 'text-green-400' : 'text-red-400'}">${tx.type}</td>
                            <td class="py-3">${tx.amount} ${tx.token}</td>
                            <td class="py-3">$${tx.price}</td>
                            <td class="py-3 text-gray-400 text-sm">${tx.time}</td>
                        `;
                        table.appendChild(row);
                    });
                });
            
            // Chat functionality
            const socket = io();
            const chatForm = document.getElementById('chat-form');
            const chatInput = document.getElementById('chat-input');
            const chatMessages = document.getElementById('chat-messages');
            
            chatForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const message = chatInput.value.trim();
                if (message) {
                    socket.emit('message', message);
                    chatInput.value = '';
                }
            });
            
            socket.on('message', (data) => {
                const messageElement = document.createElement('div');
                messageElement.className = 'text-sm';
                messageElement.innerHTML = `
                    <span class="font-medium text-blue-400">${data.user}</span>
                    <span class="text-gray-400 text-xs">${data.time}</span>
                    <p class="mt-1">${data.text}</p>
                `;
                chatMessages.appendChild(messageElement);
                chatMessages.scrollTop = chatMessages.scrollHeight;
            });
        </script>
    </body>
    </html>
    ''', user=user, prices=prices)

@app.route('/markets')
def markets():
    return render_template_string('''
    <!DOCTYPE html>
    <html class="dark">
    <head>
        <title>Markets — XtraBirg</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script type="text/javascript" src="https://s3.tradingview.com/tv.js"></script>
    </head>
    <body class="bg-gray-900 text-white">
        <!-- Header -->
        <header class="bg-gray-800 shadow-lg">
            <div class="container mx-auto px-4 py-4 flex justify-between items-center">
                <div class="flex items-center space-x-2">
                    <div class="bg-gradient-to-r from-blue-500 to-purple-600 w-8 h-8 rounded-lg"></div>
                    <h1 class="text-xl font-bold">XtraBirg</h1>
                </div>
                
                <nav class="flex items-center space-x-6">
                    <a href="/" class="hover:text-blue-400 transition-colors">
                        <i class="fas fa-home mr-1"></i> Dashboard
                    </a>
                    <a href="/markets" class="text-blue-400">
                        <i class="fas fa-chart-line mr-1"></i> Markets
                    </a>
                    {% if 'user' in session %}
                        <a href="/logout" class="text-red-400 hover:text-red-300 transition-colors">
                            <i class="fas fa-sign-out-alt"></i> Logout
                        </a>
                    {% else %}
                        <a href="/" class="text-green-400 hover:text-green-300 transition-colors">
                            <i class="fas fa-sign-in-alt"></i> Login
                        </a>
                    {% endif %}
                </nav>
            </div>
        </header>
        
        <!-- Main Content -->
        <main class="container mx-auto px-4 py-8">
            <section class="mb-8">
                <h1 class="text-3xl font-bold mb-2">📊 Market Charts</h1>
                <p class="text-gray-400">Real-time cryptocurrency price data</p>
            </section>
            
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {% for symbol in ['BTCUSDT', 'ETHUSDT', 'SOLUSDT', 'DOGEUSDT'] %}
                <div class="bg-gray-800 rounded-xl shadow-lg p-4 h-96">
                    <div class="tradingview-widget-container">
                        <div id="tradingview_{{ symbol }}" class="h-full"></div>
                        <script>
                            new TradingView.widget({
                                "autosize": true,
                                "symbol": "BINANCE:{{ symbol }}",
                                "interval": "15",
                                "timezone": "Etc/UTC",
                                "theme": "dark",
                                "style": "1",
                                "locale": "en",
                                "enable_publishing": false,
                                "hide_side_toolbar": false,
                                "allow_symbol_change": true,
                                "container_id": "tradingview_{{ symbol }}",
                                "details": true,
                                "hotlist": true
                            });
                        </script>
                    </div>
                </div>
                {% endfor %}
            </div>
            
            <div class="mt-6 bg-gray-800 rounded-xl shadow-lg p-6">
                <h2 class="text-xl font-bold mb-4">💎 All Cryptocurrencies</h2>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="text-left border-b border-gray-700">
                            <tr>
                                <th class="pb-3">Token</th>
                                <th class="pb-3">Price</th>
                                <th class="pb-3">24h Change</th>
                                <th class="pb-3">Market Cap</th>
                                <th class="pb-3">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-700">
                            {% for token in ['BTC', 'ETH', 'SOL', 'DOGE', 'XTRA'] %}
                            <tr class="hover:bg-gray-750 transition-colors">
                                <td class="py-4">
                                    <div class="flex items-center">
                                        <div class="bg-gray-700 w-8 h-8 rounded-full mr-3"></div>
                                        <span class="font-medium">{{ token }}</span>
                                    </div>
                                </td>
                                <td class="py-4">${{ "%.4f"|format(get_price(token)) }}</td>
                                <td class="py-4 {{ range(-1, 1)|random > 0 ? 'text-green-400' : 'text-red-400' }}">
                                    {{ range(-5, 5)|random|abs }}.{{ range(10, 99)|random }}%
                                </td>
                                <td class="py-4">${{ range(1, 500)|random }}B</td>
                                <td class="py-4">
                                    <a href="/#buy" class="text-blue-400 hover:text-blue-300 mr-3">
                                        <i class="fas fa-arrow-up mr-1"></i> Buy
                                    </a>
                                    <a href="/#sell" class="text-red-400 hover:text-red-300">
                                        <i class="fas fa-arrow-down mr-1"></i> Sell
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
        
        <!-- Footer -->
        <footer class="bg-gray-800 mt-12 py-8">
            <div class="container mx-auto px-4">
                <div class="flex flex-col md:flex-row justify-between items-center">
                    <div class="mb-4 md:mb-0">
                        <div class="flex items-center space-x-2">
                            <div class="bg-gradient-to-r from-blue-500 to-purple-600 w-6 h-6 rounded-lg"></div>
                            <h2 class="text-lg font-bold">XtraBirg</h2>
                        </div>
                        <p class="text-gray-400 text-sm mt-1">Modern cryptocurrency exchange</p>
                    </div>
                    
                    <div class="flex space-x-6">
                        <a href="#" class="text-gray-400 hover:text-white transition-colors">
                            <i class="fab fa-twitter"></i>
                        </a>
                        <a href="#" class="text-gray-400 hover:text-white transition-colors">
                            <i class="fab fa-telegram"></i>
                        </a>
                        <a href="#" class="text-gray-400 hover:text-white transition-colors">
                            <i class="fab fa-github"></i>
                        </a>
                    </div>
                </div>
                
                <hr class="border-gray-700 my-6">
                
                <div class="grid grid-cols-2 md:grid-cols-4 gap-6">
                    <div>
                        <h3 class="text-gray-400 font-medium mb-3">Services</h3>
                        <ul class="space-y-2">
                            <li><a href="#" class="hover:text-blue-400 transition-colors">Exchange</a></li>
                            <li><a href="#" class="hover:text-blue-400 transition-colors">Staking</a></li>
                            <li><a href="#" class="hover:text-blue-400 transition-colors">API</a></li>
                        </ul>
                    </div>
                    
                    <div>
                        <h3 class="text-gray-400 font-medium mb-3">Information</h3>
                        <ul class="space-y-2">
                            <li><a href="#" class="hover:text-blue-400 transition-colors">Fees</a></li>
                            <li><a href="#" class="hover:text-blue-400 transition-colors">Status</a></li>
                            <li><a href="#" class="hover:text-blue-400 transition-colors">Blog</a></li>
                        </ul>
                    </div>
                    
                    <div>
                        <h3 class="text-gray-400 font-medium mb-3">Legal</h3>
                        <ul class="space-y-2">
                            <li><a href="#" class="hover:text-blue-400 transition-colors">Terms</a></li>
                            <li><a href="#" class="hover:text-blue-400 transition-colors">Privacy</a></li>
                            <li><a href="#" class="hover:text-blue-400 transition-colors">AML</a></li>
                        </ul>
                    </div>
                    
                    <div>
                        <h3 class="text-gray-400 font-medium mb-3">Support</h3>
                        <ul class="space-y-2">
                            <li><a href="#" class="hover:text-blue-400 transition-colors">Help Center</a></li>
                            <li><a href="#" class="hover:text-blue-400 transition-colors">Contact Us</a></li>
                            <li><a href="#" class="hover:text-blue-400 transition-colors">FAQ</a></li>
                        </ul>
                    </div>
                </div>
                
                <hr class="border-gray-700 my-6">
                
                <p class="text-gray-500 text-center text-sm">
                    © 2023 XtraBirg. All rights reserved.
                </p>
            </div>
        </footer>
        
        <script>
            // Initialize TradingView widgets
            document.addEventListener('DOMContentLoaded', () => {
                const symbols = ['BTCUSDT', 'ETHUSDT', 'SOLUSDT', 'DOGEUSDT'];
                symbols.forEach(symbol => {
                    new TradingView.widget({
                        "width": "100%",
                        "height": "100%",
                        "symbol": `BINANCE:${symbol}`,
                        "interval": "15",
                        "timezone": "Etc/UTC",
                        "theme": "dark",
                        "style": "1",
                        "locale": "en",
                        "enable_publishing": false,
                        "hide_side_toolbar": false,
                        "allow_symbol_change": true,
                        "container_id": `tradingview_${symbol}`,
                        "details": true,
                        "hotlist": true
                    });
                });
            });
        </script>
    </body>
    </html>
    ''')

@app.route('/get-price')
def get_price_endpoint():
    token = request.args.get('token')
    return jsonify({"price": get_price(token)})

if name == 'main':
with app.app_context():
db.create_all()
socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
