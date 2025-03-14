import warnings
from sqlalchemy.exc import SAWarning
warnings.filterwarnings('ignore', category=SAWarning)
warnings.filterwarnings('ignore', message=".*The Query.get.*")
from flask import Flask, render_template, redirect, url_for, request, send_from_directory, flash, jsonify, make_response, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from forms import LoginForm, RegistrationForm, LanguageForm, ChatForm
from chatbot import get_response, get_available_models
import os
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import psutil
import hashlib
from itsdangerous import URLSafeTimedSerializer
import openai
from dotenv import load_dotenv
import json
from datetime import datetime as dt
import tensorflow as tf
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, scoped_session, declarative_base
import sqlite3

# Check for GPU availability and video memory size
def set_device():
    gpus = tf.config.experimental.list_physical_devices('GPU')
    if gpus:
        try:
            for gpu in gpus:
                details = tf.config.experimental.get_device_details(gpu)
                if details.get('memory_limit', 0) < 4 * 1024 * 1024 * 1024:  # Less than 4GB
                    raise ValueError("GPU memory less than 4GB")
            tf.config.experimental.set_visible_devices(gpus, 'GPU')
            print("Device set to use GPU")
        except Exception as e:
            tf.config.experimental.set_visible_devices([], 'GPU')
            print(f"Device set to use CPU due to: {e}")
    else:
        print("Device set to use CPU")

set_device()

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configure OpenAI API
try:
    # Try to decode the Base64-encoded API key
    encoded_api_key = os.getenv("OPENAI_API_KEY")
    if encoded_api_key:
        openai.api_key = base64.b64decode(encoded_api_key).decode("utf-8")
        print("OpenAI API key successfully decoded")
    else:
        print("Warning: OPENAI_API_KEY not found in environment variables")
        openai.api_key = None
except Exception as e:
    print(f"Error decoding API key: {e}")
    # Fallback: try to use the key directly in case it's not actually Base64 encoded
    openai.api_key = os.getenv("OPENAI_API_KEY")
    print("Using API key directly without Base64 decoding")

def generate_secret_key():
    return base64.b64encode(os.urandom(24)).decode('utf-8')

app.config['SECRET_KEY'] = generate_secret_key()
# Change database path to be in the instance folder
app.config['INSTANCE_PATH'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(app.config["INSTANCE_PATH"], "chat_database.db")}'
app.config['UPLOAD_FOLDER'] = os.path.join(app.config['INSTANCE_PATH'], 'uploads')
app.config['COOKIE_SECRET'] = generate_secret_key()

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Ensure instance folder exists
if not os.path.exists(app.config['INSTANCE_PATH']):
    os.makedirs(app.config['INSTANCE_PATH'])

# Ensure uploads folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Serializer for cookies
serializer = URLSafeTimedSerializer(app.config['COOKIE_SECRET'])

# Available GPT models
GPT_MODELS = [
    {"id": "gpt-4o", "name": "GPT-4o (Default)", "description": "Latest and most capable model"},
    {"id": "gpt-4", "name": "GPT-4", "description": "High capability model"},
    {"id": "gpt-3.5-turbo", "name": "GPT-3.5 Turbo", "description": "Faster and more economical"}
]

Base = declarative_base()

class User(UserMixin, Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, nullable=False)
    display_name = Column(String(150), nullable=True)  # Add display_name field
    password = Column(String(150), nullable=False)
    tts_enabled = Column(Boolean, default=True)
    preferred_model = Column(String(50), default="gpt-4o")
    
    def set_password(self, password):
        # Use SHA256 method instead of default scrypt to ensure compatibility
        self.password = generate_password_hash(password, method='sha256')
        
    def check_password(self, password):
        # Add error handling for hash checking
        try:
            return check_password_hash(self.password, password)
        except ValueError:
            # If there's a hash type error, return False to prompt re-login
            print("Password hash format error - consider resetting the user's password")
            return False
        
    def set_username(self, username):
        self.display_name = username  # Store original username
        # Encrypt username in the database
        self.username = hashlib.sha256(username.encode()).hexdigest()

# Additional model to store chat messages in the database instead of memory
class ChatMessage(Base):
    __tablename__ = 'chat_message'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    role = Column(String(20), nullable=False)  # 'user' or 'assistant'
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=dt.utcnow)
    chat_session = Column(String(50), nullable=False)  # To group messages by session

class UserCookie(Base):
    __tablename__ = 'user_cookie'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    cookie_data = Column(String(500), nullable=False)

class UserLanguage(Base):
    __tablename__ = 'user_language'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    language = Column(String(50), nullable=False)
    computer_name = Column(String(150), nullable=False)

class SavedChat(Base):
    __tablename__ = 'saved_chat'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    name = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=dt.utcnow)

# Add a model for IP addresses
class IPAddress(Base):
    __tablename__ = 'ip_address'
    id = Column(Integer, primary_key=True)
    ip = Column(String(50), unique=True, nullable=False)
    status = Column(String(20), nullable=False)  # 'whitelist' or 'blacklist'
    timestamp = Column(DateTime, default=dt.utcnow)
    attempts = Column(Integer, default=0)
    notes = Column(String(255), nullable=True)

# Initialize SQLAlchemy
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base.query = db_session.query_property()

# Initialize database
def init_db():
    Base.metadata.create_all(bind=engine)

# Function to recreate admin user with correct password hash
def recreate_admin_user():
    # Check if admin exists
    admin = db_session.query(User).filter_by(username=hashlib.sha256('admin'.encode()).hexdigest()).first()
    
    if admin:
        # Update admin's password hash to use sha256 method
        admin.password = generate_password_hash('reewskali15@gm', method='sha256')
        db_session.commit()
        print("Admin password hash updated to sha256")
    else:
        # Create new admin user
        admin = User()
        admin.set_username('admin')
        admin.set_password('reewskali15@gm')  # This now uses sha256
        admin.tts_enabled = True
        admin.preferred_model = "gpt-4o"
        db_session.add(admin)
        db_session.commit()
        print("Admin account created with sha256 hash")

@login_manager.user_loader
def load_user(user_id):
    return db_session.get(User, int(user_id))

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(os.path.join(app.root_path, 'static'), filename)

# Replace in-memory chat storage with database functions
def get_chat_history(user_id, session_id='default'):
    """Get chat history from database for a user"""
    messages = db_session.query(ChatMessage).filter_by(
        user_id=user_id,
        chat_session=session_id
    ).order_by(ChatMessage.timestamp).all()
    
    return [{'role': msg.role, 'content': msg.content} for msg in messages]

def add_chat_message(user_id, role, content, session_id='default'):
    """Add a message to the chat history in the database"""
    message = ChatMessage(
        user_id=user_id,
        role=role,
        content=content,
        chat_session=session_id
    )
    db_session.add(message)
    db_session.commit()

def clear_chat_history(user_id, session_id='default'):
    """Clear chat history from database for a user"""
    db_session.query(ChatMessage).filter_by(
        user_id=user_id,
        chat_session=session_id
    ).delete()
    db_session.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error_message = None
    if form.validate_on_submit():
        user = db_session.query(User).filter_by(username=hashlib.sha256(form.username.data.encode()).hexdigest()).first()
        if user is None:
            error_message = "Username or password does not exist."
        elif not user.check_password(form.password.data):
            error_message = "Incorrect password."
        else:
            login_user(user)
            
            # Detect browser language and system language
            browser_lang = request.accept_languages.best_match(['en', 'ko', 'ja', 'zh', 'es', 'fr', 'de', 'ru', 'pt', 'it']) or 'en'
            system_language = os.getenv('LANG', browser_lang).split('.')[0]
            computer_name = os.getenv('COMPUTERNAME', 'Unknown')
            
            # Save language selection to the database
            user_language = UserLanguage(user_id=current_user.id, language=system_language, computer_name=computer_name)
            db_session.add(user_language)
            db_session.commit()

            # Update display_name if it's not set (for backward compatibility)
            if not user.display_name and form.username.data:
                user.display_name = form.username.data
                db_session.commit()

            if current_user.username == hashlib.sha256('admin'.encode()).hexdigest():
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('chat', language=system_language))
    return render_template('login.html', form=form, error_message=error_message, css_url=url_for('static', filename='style.css'))

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    form = ChatForm()
    
    # Get browser's preferred color scheme and language
    browser_dark_mode = request.headers.get('Sec-CH-Prefers-Color-Scheme', 'light') == 'dark'
    browser_lang = request.accept_languages.best_match(['en', 'ko', 'ja', 'zh', 'es', 'fr', 'de', 'ru', 'pt', 'it']) or 'en'
    
    # Get language preference from URL or database or browser
    language = request.args.get('language')
    if not language:
        user_language = db_session.query(UserLanguage).filter_by(user_id=current_user.id).order_by(UserLanguage.id.desc()).first()
        language = user_language.language if user_language else browser_lang
    
    # Get user preferencesew chat request
    user = db_session.get(User, current_user.id)
    tts_enabled = user.tts_enabled
    model_preference = user.preferred_model
    display_name = user.display_name  # Get the decoded username
    
    # Handle AJAX request for chat response
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        user_input = request.form.get('message')
        user_id = current_user.id
        
        # Get the model to use
        model = request.form.get('model', model_preference)
        
        # Store user message in database
        add_chat_message(user_id, 'user', user_input)
        
        # Check if this is a search query
        is_search_query = user_input.lower().startswith(('search ', 'find ', 'look up ')) or 'search for' in user_input.lower()
        
        if is_search_query:
            # Extract search query
            search_terms = user_input.lower().replace('search for', '').replace('search', '').replace('find', '').replace('look up', '').strip()
            # Here you would implement actual search functionality using a search API
            bot_response = f"Search results for: {search_terms}"
        else:
            # Regular chat response using selected GPT model
            bot_response = get_response(user_input, model=model)
        
        # Format bot response to start on a new line
        if bot_response.startswith("유저:") or bot_response.startswith("봇:"):
            # If the response already contains formatting markers, ensure proper spacing
            bot_response = bot_response.replace("봇:", "\n봇:")
        
        # Store bot response in database
        add_chat_message(user_id, 'assistant', bot_response)
        
        return jsonify({
            'response': bot_response,
            'is_search_result': is_search_query,
            'tts_enabled': tts_enabled
        })

    if form.validate_on_submit():
        return redirect(url_for('chat'))
        
    # Get user history from database
    user_history = get_chat_history(current_user.id)
    
    # Prepare welcome messages based on language
    welcome_messages = {
        'ko': '무엇을 도와드릴까요?',
        'en': 'How can I help you today?',
        'ja': 'どのようにお手伝いできますか？',
        'zh': '我能帮助您的吗？',
        'es': '¿En qué puedo ayudarte hoy?',
        'fr': 'Comment puis-je vous aider aujourd\'hui ?',
        'de': 'Wie kann ich Ihnen heute helfen?',
        'ru': 'Чем я могу вам помочь сегодня?',
        'pt': 'Como posso ajudá-lo hoje?',
        'it': 'Come posso aiutarti oggi?'
    }
    
    placeholder_messages = {
        'ko': '무엇이든 물어보세요',
        'en': 'Ask me anything',
        'ja': '何でも聞いてください',
        'zh': '问我任何问题',
        'es': 'Pregúntame lo que quieras',
        'fr': 'Demandez-moi n\'importe quoi',
        'de': 'Fragen Sie mich alles',
        'ru': 'Спросите меня о чем угодно',
        'pt': 'Pergunte-me qualquer coisa',
        'it': 'Chiedimi qualsiasi cosa'
    }
    
    base_lang = language.split('-')[0] if '-' in language else language[:2]
    welcome_message = welcome_messages.get(base_lang, welcome_messages['en'])
    placeholder = placeholder_messages.get(base_lang, placeholder_messages['en'])
    
    # Always set show_welcome to False to remove the welcome message completely
    show_welcome = False
    
    # Define custom CSS for bot message positioning
    custom_css = """
    .bot-message {
        margin-top: 1rem; /* Add extra space above bot messages */
    }
    .bot-icon-message {
        margin-top: 1rem; /* Move bot icon down */
    }
    """
    
    return render_template('chat.html', form=form, css_url=url_for('static', filename='style.css'), 
                           language=language, history=user_history, welcome_message=welcome_message,
                           placeholder=placeholder, models=GPT_MODELS, tts_enabled=tts_enabled,
                           show_welcome=show_welcome, dark_mode=browser_dark_mode, 
                           display_name=display_name, custom_css=custom_css)  # Pass custom CSS to template

# The internet_search route can be kept for backward compatibility,
# but we'll make it redirect to chat with the search query
@app.route('/internet_search', methods=['POST'])
@login_required
def internet_search():
    """Handle internet search requests from the chat interface"""
    query = request.form.get('search_query', '')
    
    if not query:
        flash('Please enter a search query')
        return redirect(url_for('chat'))
    
    # For AJAX requests, process directly (backward compatibility)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Here you would implement actual search functionality using a search API
        response = f"Search results for: {query}"
        return jsonify({
            'success': True,
            'results': response
        })
    
    # For non-AJAX, redirect to chat with the search query
    return redirect(url_for('chat', search_query=query))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('chat'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('chat'))
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('File successfully uploaded')
        return redirect(url_for('chat'))

# Add CPU usage monitoring
@app.route('/system_status')
@login_required
def system_status():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    status = "Normal" if cpu_usage < 80 and memory_info.percent < 80 else "Warning" if cpu_usage < 90 and memory_info.percent < 90 else "Critical"
    return jsonify(cpu_usage=cpu_usage, memory_info=memory_info._asdict(), status=status)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.username == hashlib.sha256('admin'.encode()).hexdigest():
        users = db_session.query(User).all()
        user_languages = db_session.query(UserLanguage).all()
        memory_info = psutil.virtual_memory()  # Add this line to get memory info
        status = "Normal"  # Define the status variable
        return render_template('dashboard.html', users=users, user_languages=user_languages, css_url=url_for('static', filename='style.css'), status=status, memory_info=memory_info)
    return redirect(url_for('chat'))

@app.route('/admin_panel')
@login_required
def admin_panel():
    if current_user.username == hashlib.sha256('admin'.encode()).hexdigest():
        return render_template('admin_panel.html', css_url=url_for('static', filename='style.css'))
    return redirect(url_for('chat'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=hashlib.sha256(form.username.data.encode()).hexdigest())
        user.display_name = form.username.data  # Store the display name
        user.set_password(form.password.data)
        db_session.add(user)
        db_session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, css_url=url_for('static', filename='style.css'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/toggle_tts', methods=['POST'])
@login_required
def toggle_tts():
    """Toggle text-to-speech for the current user"""
    user = db_session.get(User, current_user.id)
    user.tts_enabled = not user.tts_enabled
    db_session.commit()
    return jsonify({'success': True, 'tts_enabled': user.tts_enabled})

@app.route('/set_model', methods=['POST'])
@login_required
def set_model():
    """Set the preferred model for the current user"""
    model_id = request.form.get('model_id')
    if model_id:
        user = db_session.get(User, current_user.id)
        user.preferred_model = model_id
        db_session.commit()
        return jsonify({'success': True, 'model': model_id})
    return jsonify({'success': False, 'error': 'Model ID required'})

@app.route('/get_models', methods=['GET'])
@login_required
def get_models():
    """Get available models and user preference"""
    user = db_session.get(User, current_user.id)
    return jsonify({
        'models': GPT_MODELS,
        'preferred_model': user.preferred_model,
        'tts_enabled': user.tts_enabled
    })

@app.route('/save_chat', methods=['POST'])
@login_required
def save_chat():
    """Save the current chat with a given name"""
    chat_name = request.form.get('name')
    # Get chat content from DB instead of form
    user_id = current_user.id
    chat_messages = get_chat_history(user_id)
    
    if not chat_name or not chat_messages:
        return jsonify({'success': False, 'error': 'Missing required data'})
        
    # Convert messages to json for storage
    chat_content = json.dumps(chat_messages)
    
    # Save to database
    new_chat = SavedChat(user_id=user_id, name=chat_name, content=chat_content)
    db_session.add(new_chat)
    db_session.commit()
    
    # Also save to file for backup
    chat_dir = os.path.join(app.config['INSTANCE_PATH'], 'chat_history')
    if not os.path.exists(chat_dir):
        os.makedirs(chat_dir)
        
    filename = f"{user_id}_{chat_name}_{new_chat.id}.json"
    with open(os.path.join(chat_dir, filename), 'w', encoding='utf-8') as f:
        json.dump(chat_messages, f, ensure_ascii=False, indent=2)
        
    return jsonify({'success': True, 'id': new_chat.id})

@app.route('/get_saved_chats', methods=['GET'])
@login_required
def get_saved_chats():
    """Get all saved chats for the current user"""
    saved_chats = db_session.query(SavedChat).filter_by(user_id=current_user.id).order_by(SavedChat.timestamp.desc()).all()
    return jsonify({
        'chats': [{'id': chat.id, 'name': chat.name, 'timestamp': chat.timestamp.isoformat()} 
                 for chat in saved_chats]
    })

@app.route('/load_chat/<int:chat_id>', methods=['GET'])
@login_required
def load_chat(chat_id):
    """Load a specific saved chat"""
    chat = db_session.query(SavedChat).get(chat_id)
    if not chat or chat.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Chat not found'})
    
    # Parse the content
    try:
        content = json.loads(chat.content)
        
        # Clear current chat history
        clear_chat_history(current_user.id)
        
        # Add each message to the database
        for msg in content:
            if 'role' in msg and 'content' in msg:
                add_chat_message(current_user.id, msg['role'], msg['content'])
        
        # Get the updated history
        updated_history = get_chat_history(current_user.id)
        
        return jsonify({
            'success': True, 
            'content': json.dumps(updated_history),
            'formatted': True
        })
    except json.JSONDecodeError:
        return jsonify({'success': False, 'error': 'Invalid chat data format'})

@app.route('/clear_chat', methods=['POST'])
@login_required
def clear_chat():
    """Clear chat history for current user"""
    user_id = current_user.id
    clear_chat_history(user_id)
    return jsonify({'success': True, 'message': 'Chat history cleared'})

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.before_request
def log_client_ip():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    print(f"Client IP: {client_ip}")

# Middleware to restrict access to only valid routes
@app.before_request
def restrict_invalid_routes():
    valid_routes = [rule.rule for rule in app.url_map.iter_rules()]
    # Check if path is not a valid route and not a static file
    if request.path not in valid_routes and not request.path.startswith('/static/'):
        # Use Flask's abort function to trigger the 404 error handler
        abort(404)

# Additional middleware to block .git access attempts
@app.before_request
def block_git_access():
    """Block attempts to access .git directories"""
    if '.git' in request.path:
        # Log the attempt
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        print(f"Blocked .git access attempt from IP: {client_ip}, Path: {request.path}")
        # Return 404 error
        return abort(404)

# Initialize whitelist with your IP if not exists
def init_ip_whitelist():
    whitelist_ip = '121.137.65.116'
    if not db_session.query(IPAddress).filter_by(ip=whitelist_ip).first():
        whitelisted = IPAddress(
            ip=whitelist_ip,
            status='whitelist',
            notes='Admin IP address'
        )
        db_session.add(whitelisted)
        db_session.commit()
        print(f"Added {whitelist_ip} to whitelist")

# Check if IP is whitelisted
def is_ip_whitelisted(ip):
    ip_record = db_session.query(IPAddress).filter_by(ip=ip, status='whitelist').first()
    return ip_record is not None

# Check if IP is blacklisted
def is_ip_blacklisted(ip):
    ip_record = db_session.query(IPAddress).filter_by(ip=ip, status='blacklist').first()
    return ip_record is not None

# Ban an IP
def ban_ip(ip, reason="Unauthorized path access"):
    # Check if IP record exists
    ip_record = db_session.query(IPAddress).filter_by(ip=ip).first()
    
    if ip_record:
        if ip_record.status == 'whitelist':
            # Don't ban whitelisted IPs
            return
            
        # Update existing record
        ip_record.status = 'blacklist'
        ip_record.attempts += 1
        ip_record.timestamp = dt.utcnow()
        ip_record.notes = reason
    else:
        # Create new record
        ip_record = IPAddress(
            ip=ip,
            status='blacklist',
            attempts=1,
            notes=reason
        )
        db_session.add(ip_record)
    
    db_session.commit()
    print(f"Banned IP: {ip} - {reason}")

# Track access attempt
def track_ip_attempt(ip, path):
    ip_record = db_session.query(IPAddress).filter_by(ip=ip).first()
    
    if ip_record:
        if ip_record.status == 'whitelist':
            # Don't track whitelisted IPs
            return False
            
        # Update attempts for existing record
        ip_record.attempts += 1
        ip_record.timestamp = dt.utcnow()
        
        # Immediately ban after first attempt
        if ip_record.status != 'blacklist':
            ip_record.status = 'blacklist'
            ip_record.notes = f"Banned after accessing invalid path: {path}"
            print(f"Banned IP: {ip} after accessing invalid path: {path}")
    else:
        # Create new record and immediately blacklist
        ip_record = IPAddress(
            ip=ip,
            status='blacklist',
            attempts=1,
            notes=f"Banned after accessing invalid path: {path}"
        )
        db_session.add(ip_record)
        print(f"Banned new IP: {ip} after accessing invalid path: {path}")
    
    db_session.commit()
    return True  # IP is now banned

# Replace the check_ip_ban middleware with database version
@app.before_request
def check_ip_ban():
    """Check if the IP is banned and track unauthorized access attempts"""
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    # Always allow whitelisted IPs
    if is_ip_whitelisted(client_ip):
        return None
        
    # Check if IP is banned
    if is_ip_blacklisted(client_ip):
        return redirect(url_for('page_not_found', _external=True))
        
    # For normal routes, no further checks needed
    path = request.path
    if path in [rule.rule for rule in app.url_map.iter_rules()] or path.startswith('/static/'):
        return None
        
    # Track attempt and immediately ban for invalid paths
    is_banned = track_ip_attempt(client_ip, path)
    
    # If IP is now banned, redirect to 404
    if is_banned:
        return redirect(url_for('page_not_found', _external=True))
    
    # This should not be reached with immediate banning
    return None

# Add a route to explicitly handle 404 errors that can be accessed directly
@app.route('/not_found')
def page_not_found_route():
    return render_template('404.html'), 404

# Update the errorhandler to use the same function
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Add admin routes to manage IP bans
@app.route('/admin/ip_management')
@login_required
def ip_management():
    if current_user.username != hashlib.sha256('admin'.encode()).hexdigest():
        abort(403)
        
    # Get all IPs from database
    whitelist = db_session.query(IPAddress).filter_by(status='whitelist').all()
    blacklist = db_session.query(IPAddress).filter_by(status='blacklist').order_by(IPAddress.timestamp.desc()).all()
    
    return render_template('ip_management.html', 
                          whitelist=whitelist, 
                          blacklist=blacklist,
                          css_url=url_for('static', filename='style.css'))

# Add route to whitelist an IP
@app.route('/admin/whitelist_ip', methods=['POST'])
@login_required
def whitelist_ip():
    if current_user.username != hashlib.sha256('admin'.encode()).hexdigest():
        abort(403)
        
    ip = request.form.get('ip')
    notes = request.form.get('notes', 'Manually whitelisted')
    
    if not ip:
        flash('IP address required')
        return redirect(url_for('ip_management'))
        
    # Check if IP exists
    ip_record = db_session.query(IPAddress).filter_by(ip=ip).first()
    
    if ip_record:
        # Update existing record
        ip_record.status = 'whitelist'
        ip_record.notes = notes
        ip_record.timestamp = dt.utcnow()
    else:
        # Create new record
        ip_record = IPAddress(
            ip=ip,
            status='whitelist',
            notes=notes
        )
        db_session.add(ip_record)
        
    db_session.commit()
    flash(f'IP {ip} has been whitelisted')
    return redirect(url_for('ip_management'))

# Add route to blacklist an IP
@app.route('/admin/blacklist_ip', methods=['POST'])
@login_required
def blacklist_ip():
    if current_user.username != hashlib.sha256('admin'.encode()).hexdigest():
        abort(403)
        
    ip = request.form.get('ip')
    notes = request.form.get('notes', 'Manually blacklisted')
    
    if not ip:
        flash('IP address required')
        return redirect(url_for('ip_management'))
        
    # Don't blacklist whitelisted IPs
    if ip == '121.137.65.116':
        flash('Cannot blacklist admin IP')
        return redirect(url_for('ip_management'))
        
    # Check if IP exists
    ip_record = db_session.query(IPAddress).filter_by(ip=ip).first()
    
    if ip_record:
        # Update existing record
        ip_record.status = 'blacklist'
        ip_record.notes = notes
        ip_record.timestamp = dt.utcnow()
    else:
        # Create new record
        ip_record = IPAddress(
            ip=ip,
            status='blacklist',
            notes=notes
        )
        db_session.add(ip_record)
        
    db_session.commit()
    flash(f'IP {ip} has been blacklisted')
    return redirect(url_for('ip_management'))

# Add route to delete IP record
@app.route('/admin/delete_ip/<int:ip_id>', methods=['POST'])
@login_required
def delete_ip(ip_id):
    if current_user.username != hashlib.sha256('admin'.encode()).hexdigest():
        abort(403)
        
    ip_record = db_session.query(IPAddress).get(ip_id)
    
    if ip_record:
        # Don't allow deletion of admin IP
        if ip_record.ip == '121.137.65.116' and ip_record.status == 'whitelist':
            flash('Cannot delete admin IP from whitelist')
            return redirect(url_for('ip_management'))
            
        db_session.delete(ip_record)
        db_session.commit()
        flash(f'IP record for {ip_record.ip} has been deleted')
    
    return redirect(url_for('ip_management'))

@app.route('/health_check', methods=['GET'])
def health_check():
    """Simple endpoint to check if server is online"""
    # Fix datetime usage by using dt instead of datetime
    return jsonify({'status': 'ok', 'timestamp': dt.now().isoformat()})

@app.route('/pip_commands')
@login_required
def pip_commands():
    """Display common pip commands for reference"""
    if current_user.username != hashlib.sha256('admin'.encode()).hexdigest():
        abort(403)  # Only admin can see pip commands
        
    commands = {
        'Installation': [
            {'command': 'pip install package_name', 'description': '기본 패키지 설치'},
            {'command': 'pip install package_name==1.0.0', 'description': '특정 버전 설치'},
            {'command': 'pip install -r requirements.txt', 'description': 'requirements.txt 파일에서 패키지 설치'},
            {'command': 'pip install --upgrade package_name', 'description': '패키지 업그레이드'},
        ],
        'Uninstallation': [
            {'command': 'pip uninstall package_name', 'description': '패키지 제거'},
            {'command': 'pip uninstall -r requirements.txt', 'description': 'requirements.txt에 있는 패키지 모두 제거'},
        ],
        'Information': [
            {'command': 'pip list', 'description': '설치된 패키지 목록 표시'},
            {'command': 'pip show package_name', 'description': '특정 패키지 상세 정보 표시'},
            {'command': 'pip freeze', 'description': '현재 환경의 패키지 버전 목록 생성 (requirements.txt 생성용)'},
            {'command': 'pip freeze > requirements.txt', 'description': '현재 환경을 requirements.txt 파일로 저장'},
        ],
        'Configuration': [
            {'command': 'pip config list', 'description': 'pip 설정 확인'},
            {'command': 'pip config set global.index-url URL', 'description': '패키지 인덱스 URL 설정'},
            {'command': 'pip --version', 'description': 'pip 버전 확인'},
        ],
        'Environment': [
            {'command': 'python -m venv venv', 'description': '가상 환경 생성'},
            {'command': 'venv\\Scripts\\activate', 'description': '가상 환경 활성화 (Windows)'},
            {'command': 'source venv/bin/activate', 'description': '가상 환경 활성화 (Linux/Mac)'},
            {'command': 'deactivate', 'description': '가상 환경 비활성화'},
        ]
    }
    
    return render_template('pip_commands.html', commands=commands, css_url=url_for('static', filename='style.css'))

# 로그 디렉토리 생성
log_directory = os.path.join(os.path.dirname(__file__), 'logs')
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# 로그 파일 경로
log_file_path = os.path.join(log_directory, 'access-logs.txt')

@app.before_request
def log_request_info():
    """모든 요청에 대해 IP와 경로를 로깅합니다."""
    # 클라이언트 IP 주소 가져오기
    ip = request.remote_addr
    # 요청 시간 - fix datetime usage
    timestamp = dt.now().strftime('%Y-%m-%d %H:%M:%S')
    # 요청 방식과 경로
    method = request.method
    path = request.path
    
    # 로그 형식 지정
    log_message = f"[{timestamp}] IP: {ip} | Method: {method} | Path: {path}\n"
    
    # 로그 파일에 기록
    try:
        with open(log_file_path, 'a', encoding='utf-8') as log_file:
            log_file.write(log_message)
    except Exception as e:
        print(f"로그 작성 중 오류 발생: {e}")

# Helper function for localized restart messages
def get_restart_message():
    """Returns a server restart message in the user's preferred language"""
    restart_messages = {
        'en': 'The server is restarting. Please wait a moment...',
        'ko': '서버가 다시 시작되는 중입니다. 잠시만 기다려주세요...',
        'ja': 'サーバーが再起動しています。少々お待ちください...',
        'zh': '服务器正在重新启动。请稍候...',
        'es': 'El servidor se está reiniciando. Por favor espere un momento...',
        'fr': 'Le serveur redémarre. Veuillez patienter un moment...',
        'de': 'Der Server wird neu gestartet. Bitte warten Sie einen Moment...',
        'ru': 'Сервер перезапускается. Пожалуйста, подождите...',
        'pt': 'O servidor está reiniciando. Por favor, aguarde um momento...',
        'it': 'Il server si sta riavviando. Attendere un momento...'
    }
    
    # Get user's preferred language from request
    browser_lang = request.accept_languages.best_match(list(restart_messages.keys())) or 'en'
    
    # Get base language code (e.g., 'en-US' -> 'en')
    base_lang = browser_lang.split('-')[0] if '-' in browser_lang else browser_lang[:2]
    
    # Return message in user's language or fallback to English
    return restart_messages.get(base_lang, restart_messages['en'])

# Add a new route to show restart message
@app.route('/restart')
def server_restart():
    """Show server restart message in user's preferred language"""
    message = get_restart_message()
    return render_template('restart.html', message=message, css_url=url_for('static', filename='style.css'))

if __name__ == '__main__':
    # Delete data_database.db if it exists
    old_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data_database.db')
    if (os.path.exists(old_db_path)):
        try:
            os.remove(old_db_path)
            print(f"Removed old database: {old_db_path}")
        except Exception as e:
            print(f"Error removing old database: {e}")
    
    with app.app_context():
        # Check if tables exist and create them if needed
        init_db()
        
        # Initialize IP whitelist with your approved IP
        init_ip_whitelist()
        
        # Fix admin account with proper password hash
        recreate_admin_user()
        
        # Check if we need to add the display_name column to the user table
        from sqlalchemy import inspect
        inspector = inspect(engine)
        columns = [col['name'] for col in inspector.get_columns('user')]
        
        if 'display_name' not in columns:
            # Add display_name column to the existing table
            with engine.connect() as conn:
                conn.execute("ALTER TABLE user ADD COLUMN display_name VARCHAR(150)")
                conn.commit()
                print("Added display_name column to user table")
                
                # Update existing users to set display_name from username
                conn.execute("UPDATE user SET display_name = username")
                conn.commit()
                print("Updated display_name for existing users")
        
        print("Database initialized successfully")
        print("Your whitelisted IP: 121.137.65.116")
        print("Admin account is ready with SHA256 password hash")
            
    # Enable auto-reload on code changes
    app.run(host="0.0.0.0", port=80, debug=True, use_reloader=True)