import os
import re
import json
import io
import uuid
import difflib
import random
import requests
from functools import wraps
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory, send_file, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from xhtml2pdf import pisa
from dotenv import load_dotenv
from flask_mail import Mail, Message  # Import Flask-Mail

import openai
from openai import OpenAI

from bkash_config import BKASH

load_dotenv()

# Set your OpenAI API key
openai.api_key = os.environ.get("OPENAI_API_KEY")
client = OpenAI()

# -------------------------
# Config
# -------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-default-key-fallback')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///restaurant.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Email Config
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_DEBUG'] = True # Enable verbose SMTP logs

mail = Mail(app)

import threading

def send_email(subject, recipient, body):
    """Helper to send emails with a timed wait to prevent request timeouts."""
    if not recipient or '@' not in recipient:
        print(f"Skipping email to invalid recipient: {recipient}")
        return False
        
    result = {"status": "failed"}

    def _do_send(app_context):
        with app_context:
            try:
                msg = Message(subject, recipients=[recipient])
                msg.body = body
                mail.send(msg)
                result["status"] = "success"
                print(f"Email sent to {recipient}")
            except Exception as e:
                print(f"Email error: {e}")
                result["status"] = "failed"

    # Capture app context explicitly for the thread
    ctx = app.app_context()
    thread = threading.Thread(target=_do_send, args=(ctx,))
    thread.start()
    
    # Wait for up to 5 seconds. Fast enough for Render's request cycle.
    thread.join(timeout=5)
    
    if thread.is_alive():
        print(f"Email to {recipient} timed out locally, continuing in background.")
        return "pending"
    
    return True if result["status"] == "success" else False

def format_order_body(order):
    """Helper to format order items for email."""
    try:
        items = json.loads(order.items)
        item_lines = []
        for i in items:
            # Handle potential missing keys if schema changed
            name = i.get('name', 'Unknown Item')
            qty = i.get('qty', 1)
            price = i.get('price', 0)
            item_lines.append(f"- {name} x {qty} : ${price * qty:.2f}")
        
        details = "\n".join(item_lines)
        return f"""Order #{order.unique_order_number} Details:
Placed on: {order.created_at.strftime('%Y-%m-%d %H:%M')}
{details}

Total: ${order.total:.2f}
Address: {order.address_street}, {order.address_city}
Phone: {order.phone}
"""
    except Exception as e:
        return f"Order Details: (Error parsing items: {str(e)})"



# -------------------------
# Config (Already done above)
# -------------------------

db = SQLAlchemy(app)

# ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# -------------------------
# Helpers
# -------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin login required.')
            return redirect(url_for('admin_login'))
        return fn(*args, **kwargs)
    return wrapper



# -------------------------
# Models
# -------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    member_id = db.Column(db.String(20), unique=True) # Custom ID
    email = db.Column(db.String(200), unique=True)
    password = db.Column(db.String(255), nullable=False)

    full_name = db.Column(db.String(200))
    phone = db.Column(db.String(50))
    address_district = db.Column(db.String(100))
    address_city = db.Column(db.String(100))
    address_street = db.Column(db.String(200))

    profile_image = db.Column(db.String(200))  # image filename

    # Password reset fields
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    is_admin = db.Column(db.Boolean, default=False)
    
    # Email Verification
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_code = db.Column(db.String(10), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    orders = db.relationship('Order', backref='user', lazy=True)
    reservations = db.relationship('Reservation', backref='user', lazy=True)


def is_profile_complete(user):
    if not user:
        return False

    required_fields = [
        user.full_name,
        user.email,
        user.phone,
        user.address_district,
        user.address_city,
        user.address_street
    ]

    # All fields must be non-empty, non-None, non-whitespace
    for field in required_fields:
        if not field or str(field).strip() == "":
            return False

    return True




class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('menu_item.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    score = db.Column(db.Integer, nullable=False)  # 1-5
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Float, nullable=False, default=0.0)
    category = db.Column(db.String(100), nullable=True)
    ingredients = db.Column(db.String(400), nullable=True)
    availability = db.Column(db.Boolean, default=True)  # NOTE: matches templates
    image = db.Column(db.String(300), nullable=True)
    
    ratings = db.relationship('Rating', backref='menu_item', lazy=True, cascade="all, delete-orphan")

    def get_average_rating(self):
        if not self.ratings:
            return 0
        return round(sum(r.score for r in self.ratings) / len(self.ratings), 1)

    def get_total_rating_points(self):
        return sum(r.score for r in self.ratings)

    def get_rating_count(self):
        return len(self.ratings)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    unique_order_number = db.Column(db.String(12), unique=True, nullable=False, default=lambda: str(uuid.uuid4().hex[:12]).upper())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    items = db.Column(db.Text, nullable=False)
    total = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='Placed')
    phone = db.Column(db.String(50), nullable=False)

    address_district = db.Column(db.String(100), nullable=False)
    address_city = db.Column(db.String(100), nullable=False)
    address_street = db.Column(db.String(255), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    items_parsed = db.Column(db.PickleType)




class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    unique_reservation_number = db.Column(db.String(12), unique=True, nullable=False, default=lambda: str(uuid.uuid4().hex[:12]).upper())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    time = db.Column(db.String(50), nullable=False)  # Start time (HH:MM)
    duration = db.Column(db.Integer, nullable=False)  # Duration in hours
    guests = db.Column(db.Integer, nullable=False)
    table_no = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default="Pending")  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -------------------------
# Create default admin & DB
# -------------------------

def create_admin_if_not_exists():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password=generate_password_hash('adminpass'), is_admin=True)
        db.session.add(admin)
        db.session.commit()


# Run DB setup once, when the app starts
with app.app_context():
    db.create_all()
    create_admin_if_not_exists()


@app.context_processor
def inject_global_data():
    cart = session.get('cart', {})
    count = sum(cart.values()) if isinstance(cart, dict) else 0
    
    # Simple "Best Rated" logic: Highest average rating with at least 1 vote
    all_items = MenuItem.query.all()
    best_item = None
    max_avg = 0
    
    for it in all_items:
        avg = it.get_average_rating()
        if avg > max_avg:
            max_avg = avg
            best_item = it
            
    return dict(cart_count=count, best_rated_item=best_item)


# -------------------------
# Routes - public
# -------------------------
@app.route('/')
def index():
    # show only available items on homepage
    items = MenuItem.query.filter_by(availability=True).all()
    # categories (all items)
    categories = sorted(list({(it.category or 'Uncategorized') for it in MenuItem.query.all()}))
    return render_template('index.html', items=items, categories=categories)




@app.route('/menu')
def menu():
    q = request.args.get('q', '').strip()
    cat = request.args.get('category', '').strip()
    query = MenuItem.query
    if q:
        query = query.filter(MenuItem.name.ilike(f'%{q}%'))
    if cat:
        query = query.filter_by(category=cat)
    items = query.all()
    categories = sorted(list({(it.category or 'Uncategorized') for it in MenuItem.query.all()}))
    return render_template('menu.html', items=items, categories=categories, q=q, cat=cat)


# -------------------------
# Auth (User)
# -------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password'].strip()
        if not username or not password:
            flash('Provide username and password.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        u = User(username=username, password=generate_password_hash(password))
        db.session.add(u); db.session.commit()
        
        # Generate member_id: 75 + random(10,99) + id
        u.member_id = f"75{random.randint(10, 99)}{u.id}"
        db.session.commit()
        
        flash('Registered! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password'].strip()
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin
        flash('Logged in successfully.', 'success')
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'success')
    return redirect(url_for('index'))


# -------------------------
# Password Reset
# -------------------------
import secrets

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        # Always show same message to prevent user enumeration
        # Initial success message (generic for security)
        flash('A password reset link has been sent to your email if the account exists.', 'success')
        
        if email and '@' in email:
            user = User.query.filter(db.func.lower(User.email) == email.lower()).first()
            if user:
                # Generate secure token
                token = secrets.token_urlsafe(32)
                user.reset_token = token
                user.reset_token_expiry = datetime.utcnow() + timedelta(minutes=2)
                db.session.commit()
                
                # Send reset email
                reset_url = url_for('reset_password', token=token, _external=True)
                email_body = f"""Hello {user.full_name or user.username},

You requested to reset your password. Click the link below to reset it:

{reset_url}

This link will expire in 2 minutes.

If you didn't request this, please ignore this email.

Regards,
Restaurant Team"""
                
                email_status = send_email("Password Reset Request", user.email, email_body)
                
                if email_status == "pending":
                    flash('(Note: Reset email delivery is currently queued/pending)', 'warning')
                elif not email_status:
                    flash('(Note: We had trouble sending the reset email. Please try again.)', 'warning')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    # Validate token
    if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.utcnow():
        flash('Invalid or expired reset link. Please request a new one.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # Validate password
        if not new_password:
            flash('Password is required.', 'danger')
            return render_template('reset_password.html', token=token)
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)
        
        # Update password and clear reset token
        user.password = generate_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('Password reset successful! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)


# -------------------------
# Routes - Profile
# -------------------------

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        email = request.form.get('email', '').strip()
        address_district = request.form.get('district')
        address_city = request.form.get('city')
        address_street = request.form.get('street')

        # Check if email is already taken by another user
        if email:
            existing_user = User.query.filter(db.func.lower(User.email) == email.lower(), User.id != user.id).first()
            if existing_user:
                flash("This email address is already associated with another account.", "danger")
                return render_template('edit_profile.html', user=user)

            # Check if email is being changed
            if user.email != email:
                user.email = email
                user.email_verified = False # Reset verification status if email changes
            
        user.full_name = full_name
        user.phone = phone
        user.address_district = address_district
        user.address_city = address_city
        user.address_street = address_street

        # Image upload
        img = request.files.get('profile_image')
        if img and img.filename:
            filename = secure_filename(img.filename)
            img.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.profile_image = filename

        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=user)

@app.route('/api/send-verification-code', methods=['POST'])
def api_send_verification_code():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401
    
    user = User.query.get(session['user_id'])
    
    data = request.json or {}
    email_to_verify = data.get('email', user.email).strip()

    if not email_to_verify or '@' not in email_to_verify:
        return jsonify({'success': False, 'message': 'Valid email address is required.'}), 400

    # check if email taken by another user
    existing = User.query.filter(User.email == email_to_verify, User.id != user.id).first()
    if existing:
        return jsonify({'success': False, 'message': 'This email is already used by another account.'}), 400
    
    # Generate 4-digit code
    code = str(random.randint(1000, 9999))
    user.email_verification_code = code
    # We might want to store the "pending email" somewhere if we were being strict, 
    # but for now we rely on the client sending it back during verify or just re-verifying code + email match.
    # Actually, simpler: we just send code to the email requested. 
    # When verifying, we uptake that email.
    
    db.session.commit()
    
    # Send email
    subject = "Finedine - Email Verification Code"
    body = f"Hello {user.full_name or user.username},\n\nYour 4-digit verification code is: {code}\n\nPlease enter this code in your profile to verify your email.\n\nRegards,\nRestaurant Team"
    
    email_status = send_email(subject, email_to_verify, body)
    
    if email_status:
        return jsonify({'success': True, 'message': f'Verification code sent to {email_to_verify}.'})
    else:
        return jsonify({'success': False, 'message': 'Failed to send verification email. Please try again later.'})

@app.route('/api/verify-email-code', methods=['POST'])
def api_verify_email_code():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401
    
    data = request.json
    code = data.get('code')
    new_email = data.get('email') # The email the user wants to set verified
    
    if not code:
        return jsonify({'success': False, 'message': 'Code is required'}), 400
    
    user = User.query.get(session['user_id'])
    
    if user.email_verification_code and user.email_verification_code == str(code):
        # Code matched. Update email if provided.
        if new_email and new_email != user.email:
             # Double check uniqueness
            existing = User.query.filter(User.email == new_email, User.id != user.id).first()
            if existing:
                return jsonify({'success': False, 'message': 'Email already taken by another user.'}), 400
            user.email = new_email
            
        user.email_verified = True
        user.email_verification_code = None # Clear code
        db.session.commit()
        return jsonify({'success': True, 'message': 'Email verified and updated successfully!'})
    else:
        return jsonify({'success': False, 'message': 'Invalid verification code.'})

# -------------------------
# Cart (session-based)
# -------------------------
@app.route('/cart')
def cart():
    # Check profile completion
    user = None
    complete = False

    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        complete = is_profile_complete(user)

    # Build cart item list
    raw_cart = session.get('cart', {})  # {item_id: qty}
    items = []
    total = 0.0

    for item_id, qty in raw_cart.items():
        menu_item = MenuItem.query.get(int(item_id))
        if not menu_item:
            continue

        subtotal = menu_item.price * qty
        items.append({
            'id': menu_item.id,
            'name': menu_item.name,
            'price': menu_item.price,
            'qty': qty,
            'subtotal': subtotal,
            'image': menu_item.image
        })
        total += subtotal

    return render_template(
        'cart.html',
        items=items,
        total=total,
        is_profile_complete=complete
    )


@app.route('/cart/add/<int:item_id>')
def cart_add(item_id):
    mi = MenuItem.query.get_or_404(item_id)
    if not mi.availability:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Item is not available.'}), 400
        flash('Item is not available.', 'danger')
        return redirect(url_for('menu'))
    
    cart = session.get('cart', {})
    cart[str(item_id)] = cart.get(str(item_id), 0) + 1
    session['cart'] = cart
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        count = sum(cart.values())
        item_count = cart.get(str(item_id), 0)
        return jsonify({
            'success': True, 
            'message': f'Added {mi.name} to cart.', 
            'cart_count': count,
            'item_count': item_count
        })
    
    flash(f'Added {mi.name} to cart.', 'success')
    return redirect(request.referrer or url_for('menu'))


@app.route('/cart/remove/<int:item_id>')
def cart_remove(item_id):
    cart = session.get('cart', {})
    cart.pop(str(item_id), None)
    session['cart'] = cart
    flash('Item removed from cart.', 'info')
    return redirect(url_for('cart'))


@app.route('/cart/decrease/<int:item_id>')
def cart_decrease(item_id):
    cart = session.get('cart', {})
    str_id = str(item_id)
    
    if str_id in cart:
        cart[str_id] = cart[str_id] - 1
        if cart[str_id] <= 0:
            cart.pop(str_id, None)
            flash('Item removed from cart.', 'info')
        else:
            flash('Quantity updated.', 'success')
            
    session['cart'] = cart
    return redirect(url_for('cart'))


@app.route('/cart/update', methods=['POST'])
def cart_update():
    cart = {}
    for k, v in request.form.items():
        if k.startswith('qty_'):
            item_id = k.split('_', 1)[1]
            try:
                qty = int(v)
            except:
                qty = 0
            if qty > 0:
                cart[item_id] = qty
    session['cart'] = cart
    flash('Cart updated.', 'success')
    return redirect(url_for('cart'))


# -------------------------
# Checkout / Orders
# -------------------------


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        flash('Please login to place order.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])

    # If profile incomplete → block checkout
    if not is_profile_complete(user):
        flash("Please complete your profile before placing an order.", 'warning')
        return redirect(url_for('profile'))
    cart_data = session.get('cart', {})
    if not cart_data:
        flash("Your cart is empty.", 'warning')
        return redirect(url_for('cart'))

    if request.method == 'POST':
        payment_method = request.form.get("payment_method") 
        phone = request.form.get('phone')
        district = request.form.get('district')
        city = request.form.get('city')
        street = request.form.get('street')

         # If Pay Now selected → go to payment gateway page
        if payment_method == "paynow":
            session["checkout_data"] = {
                "phone": phone,
                "district": district,
                "city": city,
                "street": street
            }
            return redirect(url_for("pay_now"))

        # Build the order items list
        items_list = []
        total_price = 0

        for item_id, qty in cart_data.items():
            item = MenuItem.query.get(int(item_id))
            if item:
                items_list.append({
                    'name': item.name,
                    'price': item.price,
                    'qty': qty
                })
                total_price += item.price * qty

        # Create order
        new_order = Order(
            user_id=user.id,
            items=json.dumps(items_list),
            total=total_price,
            phone=phone,
            address_district=district,
            address_city=city,
            address_street=street,
            status="Pending"
        )

        db.session.add(new_order)
        db.session.commit()

        # Clear cart
        session['cart'] = {}

        flash("Order placed successfully!", 'success')
        return redirect(url_for('orders'))

    # GET method → show checkout page
    return render_template("checkout.html")

    


def bkash_get_token():
    url = f"{BKASH['base_url']}/token/grant"
    headers = {"Content-Type": "application/json"}
    body = {
        "app_key": BKASH["app_key"],
        "app_secret": BKASH["app_secret"]
    }

    res = requests.post(url, json=body, auth=(BKASH["username"], BKASH["password"]), headers=headers)
    data = res.json()

    return data.get("id_token")


@app.route('/pay-now')
def pay_now():
    if "checkout_data" not in session:
        return redirect(url_for("checkout"))

    # Calculate total from cart
    cart = session.get('cart', {})
    total = 0
    for item_id, qty in cart.items():
        item = MenuItem.query.get(int(item_id))
        if item:
            total += item.price * qty

    return render_template("pay_now.html", total=total)



@app.route('/payment/success')
def fake_payment_success():
    if "checkout_data" not in session:
        return redirect(url_for("checkout"))

    checkout = session["checkout_data"]
    cart_data = session.get("cart", {})
    user = User.query.get(session['user_id'])

    items_list = []
    total_price = 0

    for item_id, qty in cart_data.items():
        item = MenuItem.query.get(int(item_id))
        if item:
            items_list.append({
                'name': item.name,
                'price': item.price,
                'qty': qty
            })
            total_price += item.price * qty

    new_order = Order(
        user_id=user.id,
        items=json.dumps(items_list),
        total=total_price,
        phone=checkout["phone"],
        address_district=checkout["district"],
        address_city=checkout["city"],
        address_street=checkout["street"],
        status="Paid"
    )

    db.session.add(new_order)
    db.session.commit()

    session.pop("checkout_data", None)
    session['cart'] = {}

    flash("Payment successful! Order placed.", 'success')
    return redirect(url_for('orders'))




@app.route('/pay/bkash', methods=['POST'])
def bkash_pay():
    if "checkout_data" not in session:
        return redirect(url_for("checkout"))

    token = bkash_get_token()
    if not token:
        flash("bKash authentication failed!", 'danger')
        return redirect(url_for("checkout"))

    # Calculate Total Amount
    cart = session.get("cart", {})
    total = 0
    for item_id, qty in cart.items():
        item = MenuItem.query.get(int(item_id))
        if item:
            total += item.price * qty

    # Store transaction amount for verification
    session["bkash_amount"] = total

    # Create payment request
    create_url = f"{BKASH['base_url']}/checkout/payment/create"
    headers = {
        "Content-Type": "application/json",
        "authorization": token,
        "x-app-key": BKASH["app_key"]
    }

    payload = {
        "amount": str(total),
        "currency": "BDT",
        "intent": "sale",
        "merchantInvoiceNumber": "INV" + str(int(datetime.utcnow().timestamp())),
    }

    # Send create payment request
    res = requests.post(create_url, json=payload, headers=headers)
    data = res.json()

    if "bkashURL" in data:
        # Redirect user to bKash hosted UI
        return redirect(data["bkashURL"])

    flash("bKash payment initiation failed.", 'danger')
    return redirect(url_for("checkout"))


@app.route('/bkash/callback', methods=['GET'])
def bkash_callback():
    payment_id = request.args.get("paymentID")
    status = request.args.get("status")

    if status != "success":
        flash("bKash Payment Failed or Canceled.", 'danger')
        return redirect(url_for("checkout"))

    # Execute API
    token = bkash_get_token()

    execute_url = f"{BKASH['base_url']}/checkout/payment/execute/{payment_id}"
    headers = {
        "Content-Type": "application/json",
        "authorization": token,
        "x-app-key": BKASH["app_key"]
    }

    res = requests.post(execute_url, json={}, headers=headers)
    data = res.json()

    if data.get("transactionStatus") != "Completed":
        flash("bKash Payment Execution Failed.", 'danger')
        return redirect(url_for("checkout"))

    # Payment successful → Create Order
    return finalize_bkash_order()

def finalize_bkash_order():
    checkout = session.get("checkout_data")
    cart = session.get("cart", {})
    user = User.query.get(session['user_id'])

    items_list = []
    total_price = 0
    for item_id, qty in cart.items():
        item = MenuItem.query.get(int(item_id))
        if item:
            items_list.append({
                "name": item.name,
                "price": item.price,
                "qty": qty
            })
            total_price += item.price * qty

    new_order = Order(
        user_id=user.id,
        items=json.dumps(items_list),
        total=total_price,
        phone=checkout["phone"],
        address_district=checkout["district"],
        address_city=checkout["city"],
        address_street=checkout["street"],
        status="Paid"
    )

    db.session.add(new_order)
    db.session.commit()

    # Clear session
    session.pop("checkout_data", None)
    session["cart"] = {}

    flash("Payment Successful! Order placed.", "success")
    return redirect(url_for("orders"))






@app.route('/orders')
def orders():
    if 'user_id' not in session:
        flash('Please login.')
        return redirect(url_for('login'))
    user_orders = Order.query.filter_by(user_id=session['user_id']).order_by(Order.created_at.desc()).all()
    # parse items JSON server-side and attach
    for o in user_orders:
        try:
            o.items_parsed = json.loads(o.items)
        except:
            o.items_parsed = []
    return render_template('orders.html', orders=user_orders)




@app.route('/invoice/<int:order_id>')
def download_invoice(order_id):
    if 'user_id' not in session:
        flash("Please login to download invoice.", 'danger')
        return redirect(url_for('login'))

    order = Order.query.get_or_404(order_id)

    # Prevent users from downloading others’ invoices
    if order.user_id != session['user_id'] and not session.get('is_admin'):
        flash("You don't have permission to access this invoice.", 'danger')
        return redirect(url_for('orders'))

    # Parse items JSON
    try:
        order.items_parsed = json.loads(order.items)
    except:
        order.items_parsed = []


    # Render invoice HTML
    html_out = render_template('invoice.html', order=order)

    # PDF generation
    pdf_stream = io.BytesIO()
    pisa.CreatePDF(html_out, dest=pdf_stream)
    pdf_stream.seek(0)

    return send_file(
        pdf_stream,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"Invoice_{order.unique_order_number}.pdf"
    )

# -------------------------
# Reservations
# -------------------------

@app.route('/reserve', methods=['GET', 'POST'])
def reserve():
    if 'user_id' not in session:
        flash('Please login to make a reservation.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    # Profile check
    if not is_profile_complete(user):
        flash('Please complete your profile before reserving a table.', 'warning')
        return redirect(url_for('edit_profile'))

    if request.method == 'POST':
        date = request.form['date']
        time = request.form['time']
        duration = int(request.form['duration'])
        guests = int(request.form['guests'])
        table_no = request.form['table_no']

        # Use shared validation logic
        is_valid, msg = check_table_availability(date, time, duration, table_no)
        
        if not is_valid:
            flash(msg, 'danger')
            return redirect(url_for('reserve'))

        # Create reservation
        new_res = Reservation(
            user_id=user.id,
            date=date,
            time=time,
            duration=duration,
            guests=guests,
            table_no=table_no,
            status="Pending"
        )

        db.session.add(new_res)
        db.session.commit()

        flash("Reservation successful!", 'success')
        return redirect(url_for('reservations'))

    return render_template('reserve.html')



# wait ad











@app.route('/reservation/cancel/<int:res_id>')
def cancel_reservation(res_id):
    if 'user_id' not in session:
        flash('Please login first.', 'danger')
        return redirect(url_for('login'))

    r = Reservation.query.get(res_id)

    if not r or r.user_id != session['user_id']:
        flash('Reservation not found.', 'danger')
        return redirect(url_for('reservations'))

    # Update the status to Canceled
    r.status = 'Canceled'
    db.session.commit()

    flash('Reservation has been canceled successfully.', 'success')
    return redirect(url_for('reservations'))

@app.route('/reservations')
def reservations():
    if 'user_id' not in session:
        flash('Please login.')
        return redirect(url_for('login'))
    res = Reservation.query.filter_by(user_id=session['user_id']).order_by(Reservation.created_at.desc()).all()
    return render_template('reservations.html', reservations=res)


# -------------------------
# Admin Authentication & Panel
# -------------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password'].strip()
        user = User.query.filter_by(username=username, is_admin=True).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid admin credentials.')
            return redirect(url_for('admin_login'))
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = True
        return redirect(url_for('admin_index'))
    return render_template('admin/login.html')


@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    flash('Admin logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/admin')
@admin_required
def admin_index():
    items = MenuItem.query.order_by(MenuItem.id.desc()).all()
    orders = Order.query.order_by(Order.created_at.desc()).all()
    reservations = Reservation.query.order_by(Reservation.created_at.desc()).all()

    # Parse JSON items
    for o in orders:
        try:
            o.items_parsed = json.loads(o.items)
        except:
            o.items_parsed = []

    total_sales = db.session.query(db.func.sum(Order.total)).scalar() or 0
    return render_template('admin/index.html', items=items, orders=orders, reservations=reservations, total_sales=total_sales)


# -------------------------
# Admin - Add / Edit / Delete Menu
# -------------------------
@app.route('/admin/menu/add', methods=['GET', 'POST'])
@admin_required
def admin_add_menu():
    if request.method == 'POST':
        name = request.form['name'].strip()
        price = float(request.form.get('price') or 0)
        category = request.form.get('category')
        ingredients = request.form.get('ingredients')
        availability = True if request.form.get('availability') else False

        # handle image upload
        file = request.files.get('image')
        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

        mi = MenuItem(name=name, price=price, category=category, ingredients=ingredients, availability=availability, image=filename)
        db.session.add(mi); db.session.commit()
        flash('Menu item added.', 'success')
        return redirect(url_for('admin_index'))
    return render_template('admin/add_menu.html')


@app.route('/admin/menu/edit/<int:item_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_menu(item_id):
    mi = MenuItem.query.get_or_404(item_id)
    if request.method == 'POST':
        mi.name = request.form['name'].strip()
        mi.price = float(request.form.get('price') or 0)
        mi.category = request.form.get('category')
        mi.ingredients = request.form.get('ingredients')
        mi.availability = True if request.form.get('availability') else False

        file = request.files.get('image')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            mi.image = filename

        db.session.commit()
        flash('Menu item updated.', 'success')
        return redirect(url_for('admin_index'))
    return render_template('admin/edit_menu.html', item=mi)


@app.route('/admin/menu/delete/<int:item_id>')
@admin_required
def admin_delete_menu(item_id):
    mi = MenuItem.query.get_or_404(item_id)
    # Optionally remove image file (not required)
    if mi.image:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], mi.image))
        except:
            pass
    db.session.delete(mi); db.session.commit()
    flash('Menu item deleted.', 'success')
    return redirect(url_for('admin_index'))


@app.route('/admin/sales')
@admin_required
def sales_report():
    orders = Order.query.all()
    total_sales = db.session.query(db.func.sum(Order.total)).scalar() or 0
    
    # Calculate popular dishes
    dish_counts = {}
    for o in orders:
        try:
            items = json.loads(o.items)
            for item in items:
                name = item.get('name')
                qty = item.get('qty', 0)
                if name:
                    dish_counts[name] = dish_counts.get(name, 0) + qty
        except:
            continue
            
    popular = []
    for k, v in dish_counts.items():
        item = MenuItem.query.filter_by(name=k).first()
        avg = item.get_average_rating() if item else 0
        points = item.get_total_rating_points() if item else 0
        popular.append({
            'name': k, 
            'count': v, 
            'avg_rating': avg, 
            'total_points': points
        })
    
    popular = sorted(popular, key=lambda x: x['count'], reverse=True)
    
    return render_template('admin/sales.html', total_sales=total_sales, popular=popular)


@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/admins')
@admin_required
def admin_admins():
    admins = User.query.filter_by(is_admin=True).order_by(User.id.desc()).all()
    # We need to fetch all users for the "Promote" search functionality
    users = User.query.filter_by(is_admin=False).order_by(User.username).all()
    return render_template('admin/admins.html', admins=admins, users=users)


@app.route('/admin/orders')
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    for o in orders:
        try:
            o.items_parsed = json.loads(o.items)
        except:
            o.items_parsed = []
    return render_template('admin/orders.html', orders=orders)


@app.route('/admin/reservations')
@admin_required
def admin_reservations():
    reservations = Reservation.query.order_by(Reservation.created_at.desc()).all()
    return render_template('admin/reservations.html', reservations=reservations)

@app.route('/admin/order/delete/<int:order_id>', methods=['POST', 'GET'])
@admin_required
def admin_delete_order(order_id):
    # Find the order by ID
    order = Order.query.get(order_id)

    if order:
        # Notify User First
        user = User.query.get(order.user_id)
        email_status = False
        if user and user.email:
            details = format_order_body(order)
            email_status = send_email(f"Order #{order.unique_order_number} Canceled", user.email,
                       f"Hello {user.full_name},\n\nYour order #{order.unique_order_number} has been CANCELED/DELETED by the admin.\n\n{details}\n\nIf you have already paid, a refund will be processed shortly.\n\nRegards,\nRestaurant Team")

        # Deleting the order from the database
        db.session.delete(order)
        db.session.commit()
        
        flash('Order has been deleted.', 'success')
        
        # Email Notification Status
        if email_status == "pending":
            flash(f"Notification queued for {user.email}", 'warning')
        elif email_status:
            flash(f"Notification sent to {user.email}", 'success')
        else:
            flash(f"Note: Email couldn't be sent to {user.email}", 'warning')

    else:
        flash('Order not found.', 'danger')

    return redirect(request.referrer or url_for('admin_index'))


@app.route('/admin/order/confirm/<int:order_id>')
@admin_required
def admin_confirm_order(order_id):
    order = Order.query.get_or_404(order_id)
    order.status = 'Confirmed'
    db.session.commit()
    
    # Notify User
    user = User.query.get(order.user_id)
    email_status = False
    if user and user.email:
        details = format_order_body(order)
        email_status = send_email(f"Order #{order.unique_order_number} Confirmed", user.email, 
                   f"Hello {user.full_name},\n\nYour order #{order.unique_order_number} has been confirmed. We are starting to prepare it!\n\n{details}\n\nRegards,\nRestaurant Team")

    msg = 'Order confirmed.'
    flash(msg, 'success')
    
    # Email Notification Status
    if email_status == "pending":
        flash(f"Confirmation email queued for {user.email}", 'warning')
    elif email_status:
        flash(f"Confirmation email sent to {user.email}", 'success')
    else:
        flash(f"Note: Email error for {user.email}", 'warning')
        
    return redirect(request.referrer or url_for('admin_index'))


@app.route('/admin/reservation/cancel/<int:res_id>')
@admin_required
def admin_cancel_reservation(res_id):
    res = Reservation.query.get_or_404(res_id)
    res.status = 'Canceled'
    db.session.commit()

    # Notify User
    user = User.query.get(res.user_id)
    email_status = False
    if user and user.email:
        email_status = send_email("Reservation Canceled", user.email,
                   f"Hello {user.full_name},\n\nYour reservation for Table {res.table_no} on {res.date} at {res.time} has been CANCELED by the admin.\n\nRegards,\nRestaurant Team")

    flash('Reservation has been canceled.', 'success')

    # Email Notification Status
    if email_status == "pending":
        flash(f"Notification queued for {user.email}", 'warning')
    elif email_status:
        flash(f"Notification sent to {user.email}", 'success')
    else:
        flash(f"Note: Email error for {user.email}", 'warning')

    return redirect(request.referrer or url_for('admin_index'))


@app.route('/admin/reservation/confirm/<int:res_id>')
@admin_required
def admin_confirm_reservation(res_id):
    res = Reservation.query.get_or_404(res_id)
    res.status = 'Confirmed'
    db.session.commit()

    # Notify User
    user = User.query.get(res.user_id)
    email_status = False
    if user and user.email:
        email_status = send_email("Reservation Confirmed", user.email,
                   f"Hello {user.full_name},\n\nYour reservation for Table {res.table_no} on {res.date} at {res.time} has been CONFIRMED.\n\nWe look forward to hosting you!\n\nRegards,\nRestaurant Team")

    flash('Reservation confirmed.', 'success')

    # Email Notification Status
    if email_status == "pending":
        flash(f"Confirmation email queued for {user.email}", 'warning')
    elif email_status:
        flash(f"Confirmation email sent to {user.email}", 'success')
    else:
        flash(f"Note: Email error for {user.email}", 'warning')
        
    return redirect(request.referrer or url_for('admin_index'))


@app.route('/admin/reservation/remove/<int:res_id>')
@admin_required
def admin_remove_reservation(res_id):
    res = Reservation.query.get_or_404(res_id)
    user = User.query.get(res.user_id)
    
    # Notify User before deletion
    email_status = False
    if user and user.email:
        email_status = send_email("Reservation Removed", user.email,
                   f"Hello {user.full_name},\n\nYour reservation record for Table {res.table_no} on {res.date} at {res.time} has been removed from our system. The same time slot is available right now. \n\nRegards,\nRestaurant Team")

    db.session.delete(res)
    db.session.commit()
    
    flash('Reservation removed.', 'success')
    
    if email_status == "pending":
        flash(f"Notification queued for {user.email}", 'warning')
    elif email_status:
        flash(f"Notification sent to {user.email}", 'success')
    else:
        flash(f"Note: Email error for {user.email}", 'warning')
    return redirect(request.referrer or url_for('admin_index'))




# -------------------------
# Serve uploaded files (optional - static does it normally)
# -------------------------
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)





# -------------------------
# Admin AJAX API Routes
# -------------------------

@app.route('/admin/user/<username>')
@admin_required
def admin_get_user(username):
    user = User.query.filter_by(username=username.lower()).first_or_404()
    return jsonify({
        'username': user.username,
        'email': user.email,
        'full_name': user.full_name,
        'phone': user.phone,
        'address_street': user.address_street,
        'address_city': user.address_city,
        'address_district': user.address_district,
        'profile_image': user.profile_image,
        'email_verified': user.email_verified
    })

@app.route('/admin/user/<username>/update', methods=['POST'])
@admin_required
def admin_update_user(username):
    user = User.query.filter_by(username=username.lower()).first_or_404()
    data = request.json
    user.email = data.get('email')
    user.full_name = data.get('full_name')
    user.phone = data.get('phone')
    user.address_street = data.get('address_street')
    user.address_city = data.get('address_city')
    db.session.commit()

    # Notify User
    email_status = False
    if user.email:
        email_status = send_email("Profile Updated by Admin", user.email, 
                   f"Hello {user.username},\n\nYour profile details have been updated by an administrator.\n\nRegards,\nRestaurant Team")

    return jsonify({
        'success': True,
        'email_status': email_status,
        'email': user.email
    })

@app.route('/admin/user/<username>/delete', methods=['POST'])
@admin_required
def admin_delete_user_api(username):
    user = User.query.filter_by(username=username.lower()).first_or_404()
    
    # Safeguard 1: Prevent self-deletion
    if user.id == session.get('user_id'):
        return jsonify({
            'success': False,
            'message': 'You cannot delete your own account while logged in.'
        }), 400
        
    # Safeguard 2: Prevent deleting the last admin
    if user.is_admin:
        admin_count = User.query.filter_by(is_admin=True).count()
        if admin_count <= 1:
            return jsonify({
                'success': False,
                'message': 'This is the last administrator account. You cannot delete it.'
            }), 400

    email = user.email
    db.session.delete(user)
    db.session.commit()

    # Notify User
    email_status = False
    if email:
        email_status = send_email("Account Deleted", email, 
                   f"Hello {username},\n\nYour account has been deleted by an administrator. \n\nRegards,\nRestaurant Team")

    return jsonify({
        'success': True,
        'email_status': email_status,
        'email': email
    })

@app.route('/admin/user/<username>/promote', methods=['POST'])
@admin_required
def admin_promote_user_api(username):
    user = User.query.filter_by(username=username.lower()).first_or_404()
    if user.is_admin:
        return jsonify({'success': False, 'message': 'User is already an administrator.'}), 400
    
    user.is_admin = True
    db.session.commit()
    
    # Notify User
    email_status = False
    if user.email:
        email_status = send_email("Role Upgraded - Administrator", user.email, 
                   f"Hello {user.username},\n\nCongratulations! Your account has been promoted to Administrator. You now have full access to the Finedine Management Panel.\n\nRegards,\nFinedine Team")
        
    return jsonify({
        'success': True,
        'message': f'@{user.username} has been promoted to Administrator.',
        'email_status': email_status
    })


@app.route('/admin/order/<int:order_id>')
@admin_required
def admin_get_order(order_id):
    order = Order.query.get_or_404(order_id)
    try:
        items = json.loads(order.items)
    except:
        items = []
    
    user = User.query.get(order.user_id)
    return jsonify({
        'id': order.id,
        'unique_order_number': order.unique_order_number,
        'total': order.total,
        'status': order.status,
        'created_at': order.created_at.strftime('%Y-%m-%d %H:%M'),
        'customer': user.full_name if user else 'Unknown',
        'username': user.username if user else 'anon',
        'phone': order.phone,
        'address_street': order.address_street,
        'address_city': order.address_city,
        'address_district': order.address_district,
        'items': items
    })



# -------------------------
# ChatBot
# -------------------------



@app.route('/chat')
def chat():
    return render_template('chat.html')

# -------------------------
# ChatBot Logic
# -------------------------
import difflib

def get_menu_tool():
    """Returns the full menu as a string."""
    items = MenuItem.query.all()
    if not items:
        return "The menu is currently empty."
    lines = []
    for item in items:
        status = "Available" if item.availability else "Sold Out"
        lines.append(f"- {item.name} ({item.category}): ${item.price} [{status}]")
    return "\n".join(lines)

def add_to_cart_tool(item_name, quantity=1):
    """Adds an item to the user's cart by fuzzy matching the name."""
    # Find closest match
    all_items = MenuItem.query.filter_by(availability=True).all()
    all_names = [i.name for i in all_items]
    matches = difflib.get_close_matches(item_name, all_names, n=1, cutoff=0.5)

    if not matches:
        return f"Sorry, I couldn't find '{item_name}' on the menu."
    
    matched_name = matches[0]
    matched_item = next(i for i in all_items if i.name == matched_name)
    
    cart = session.get('cart', {})
    cart[str(matched_item.id)] = cart.get(str(matched_item.id), 0) + quantity
    session['cart'] = cart
    
    return f"Added {quantity} x {matched_name} to your cart. Total in cart: {cart[str(matched_item.id)]}"

def check_table_availability(date, time, duration=2, table_no=None):
    """
    Checks if a table is available.
    Returns (bool, message)
    """
    try:
        # 1. Parse DateTime
        req_start = datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M")
        req_end = req_start + timedelta(hours=duration)
        now = datetime.now()
    except ValueError:
        return False, "Invalid date/time format. Use YYYY-MM-DD and HH:MM."

    # 2. Check Past Date
    if req_start < now:
        return False, "You cannot book a table in the past."

    # 3. Check Opening Hours (11:00 to 23:00)
    # Restaurant opens at 11:00
    if req_start.hour < 11:
        return False, "We are closed. Opening hours are 11:00 AM - 11:00 PM."
    
    # Kitchen closes at 22:00, Restaurant at 23:00. 
    # Let's say last seating is 22:00.
    if req_start.hour >= 22:
        return False, "Our last seating is at 10:00 PM."

    # 4. Check Conflicts in DB
    # If table_no is "Any" or None, we skip specific table check for now 
    # (In a real app we'd find *an* empty table, but here we assume capacity if specific table not requested)
    if table_no and table_no != "Any":
        conflict = Reservation.query.filter_by(date=date, table_no=table_no).all()
        for r in conflict:
            existing_start = datetime.strptime(f"{r.date} {r.time}", "%Y-%m-%d %H:%M")
            existing_end = existing_start + timedelta(hours=r.duration)

            # Check Overlap
            # (StartA < EndB) and (EndA > StartB)
            if req_start < existing_end and req_end > existing_start:
                return False, f"Table {table_no} is already booked at that time."

    return True, "Available"

def book_table_tool(date, time, guests, table_no="Any"):
    """Creates a reservation."""
    if 'user_id' not in session:
        return "Please log in first to book a table."
    
    user = User.query.get(session['user_id'])
    if not is_profile_complete(user):
        return "Your profile is incomplete. Please update your profile with phone and address."

    # Validation
    is_valid, msg = check_table_availability(date, time, duration=2, table_no=table_no)
    if not is_valid:
        return f"Booking Failed: {msg}"
        
    try:
        new_res = Reservation(
            user_id=user.id,
            date=date,
            time=time,
            duration=2,
            guests=guests,
            table_no=table_no if table_no != "Any" else "T1", # Assign T1 default if Any
            status="Pending"
        )
        db.session.add(new_res)
        db.session.commit()
        return f"Reservation request sent for {guests} guests on {date} at {time}. Status: Pending (Waiting for admin confirmation). Table: {new_res.table_no}."
    except Exception as e:
        return f"System Error: {str(e)}"



@app.route("/api/rate", methods=["POST"])
def rate_item():
    data = request.get_json()
    item_id = data.get("item_id")
    score = data.get("score")
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({"success": False, "message": "Please log in to rate dishes."}), 401

    if not item_id or not score:
        return jsonify({"success": False, "message": "Missing item_id or score."}), 400

    try:
        score = int(score)
        if not (1 <= score <= 5):
            return jsonify({"success": False, "message": "Score must be between 1 and 5."}), 400
    except ValueError:
        return jsonify({"success": False, "message": "Score must be an integer."}), 400

    item = MenuItem.query.get(item_id)
    if not item:
        return jsonify({"success": False, "message": "Item not found."}), 404

    # Save new rating
    new_rating = Rating(
        item_id=item_id,
        user_id=user_id,
        score=score
    )
    db.session.add(new_rating)
    db.session.commit()

    return jsonify({
        "success": True, 
        "message": "Thank you for your rating!",
        "average": item.get_average_rating(),
        "count": item.get_rating_count()
    })

@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json()
    user_msg = data.get("message", "").strip().lower()
    
    # Initialize history
    if 'chat_history' not in session:
        session['chat_history'] = []
    
    response_text = ""
    redirect_url = None
    
    # Number word mapping
    word_to_num = {
        'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5,
        'six': 6, 'seven': 7, 'eight': 8, 'nine': 9, 'ten': 10,
        'a': 1, 'an': 1
    }

    # 1. Greetings
    if any(x in user_msg for x in ['hi', 'hello', 'hey', 'greetings', 'good morning', 'good evening']):
        response_text = "Hello! Welcome here. I am your AI assistant, can place orders for you. You can say 'Show Menu', or order like '2 Pizza, one Burger'."

    elif any(x in user_msg for x in ['order']):
        response_text = "I am your AI assistant, can place orders for you. You can say 'Show Menu', or order like '2 Pizza, one Burger'."

    
    # 2. View Menu
    elif any(x in user_msg for x in ['menu', 'list', 'options', 'what do you have', 'dishes', 'food list']):
        response_text = "Here is our menu:\n" + get_menu_tool()

    # 3. Booking / Reservation (Smart Detection)
    elif any(x in user_msg for x in ['book', 'reservation', 'table', 'reserve', 'schedule', 'appointment', 'visit', 'booking', 'seat']):
        response_text = "Sure, Redirecting you to reservation..."
        redirect_url = url_for('reserve')

    # 4. View Cart / Checkout (Smart Detection)
    elif any(x in user_msg for x in ['cart', 'bucket', 'shopping', 'checkout', 'buy', 'pay', 'basket', 'my items', 'items in cart']):
        response_text = "Opening your shopping cart..."
        redirect_url = url_for('cart')

    # 4. Intelligent Multi-Item Detection
    else:
        # Fetch all available items
        all_items = MenuItem.query.filter_by(availability=True).all()
        
        # Build a robust keyword map
        # "Margherita Pizza" -> keywords: ["margherita", "pizza", "margherita pizza"]
        # Also support plurals: "pizzas", "burgers"
        keyword_map = {}
        
        for item in all_items:
            name_lower = item.name.lower()
            parts = name_lower.split()
            
            # Map full name
            keyword_map[name_lower] = item
            keyword_map[name_lower + 's'] = item # Plural full name
            
            # Map individual strong keywords (len > 2 to avoid "a", "of")
            for part in parts:
                if len(part) > 2:
                    # If keyword conflict (e.g. "Chicken" in "Chicken Pizza" and "Chicken Burger"), 
                    # we might overwrite. Last one wins. 
                    # Ideally we wouldn't map ambiguous words, but for this scale it's fine.
                    # Or we could map to a list? Let's keep it simple: Map to item.
                    if part not in keyword_map:
                        keyword_map[part] = item
                    if (part + 's') not in keyword_map:
                         keyword_map[part + 's'] = item
                         
        # Sort keywords by length descending to match "Margherita Pizza" before "Pizza"
        sorted_keywords = sorted(keyword_map.keys(), key=len, reverse=True)
        
        found_items = []
        msg_scan = user_msg 
        
        for keyword in sorted_keywords:
            # Regex for: (Quantity)? + keyword
            pattern = rf"(?:(\d+|one|two|three|four|five|six|seven|eight|nine|ten|a|an)\s+)?\b{re.escape(keyword)}\b"
            
            matches = list(re.finditer(pattern, msg_scan))
            for match in matches:
                qty_str = match.group(1)
                qty = 1
                if qty_str:
                    if qty_str.isdigit():
                        qty = int(qty_str)
                    else:
                        qty = word_to_num.get(qty_str, 1)
                
                item = keyword_map[keyword]
                found_items.append((item, qty))
                
                # Mask out match
                start, end = match.span()
                msg_scan = msg_scan[:start] + (" " * (end - start)) + msg_scan[end:]

        if found_items:
            # Add all found items to cart
            results = []
            # Deduplicate by adding quantities if same item matched multiple times?
            # E.g. "Pizza and Pizza" -> 2 items.
            # But here we just list them.
            
            total_added = {}
            for item, qty in found_items:
                # Add to DB/Session via tool
                add_to_cart_tool(item.name, qty)
                
                # Track for response message
                if item.name in total_added:
                    total_added[item.name] += qty
                else:
                    total_added[item.name] = qty

            results_str = ", ".join([f"{v} x {k}" for k, v in total_added.items()])
            response_text = f"Great! Added {results_str} to your cart."
        
        # 5. Explicit "Add" but no items found
        elif 'add' in user_msg:
             response_text = "I couldn't identify those items on our menu. Please check the spelling or ask to 'Show Menu'."
        
        # 6. Fallback
        else:
            response_text = "I'm sorry, I didn't catch that. Try saying 'Menu', '3 Burgers', or 'Book a table'."

    # Save to history
    session['chat_history'].append({"role": "user", "content": user_msg})
    session['chat_history'].append({"role": "assistant", "content": response_text})
    
    # Generate simple options
    options = ["View Menu", "View Cart", "Book a Table"]
    
    return jsonify({
        "answer": response_text, 
        "options": options,
        "redirect": redirect_url
    })



# -------------------------
# Error Handlers
# -------------------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


# -------------------------
# Run server
# -------------------------
if __name__ == '__main__':
    # If you change models and need a fresh DB: delete restaurant.db manually then restart.
    with app.app_context():
        db.create_all()
        create_admin_if_not_exists()
    app.run(debug=True)
