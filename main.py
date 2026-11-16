from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Length
import os
import sys
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_bootstrap import Bootstrap5
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['WTF_CSRF_TIME_LIMIT'] = None

# SECRET_KEY must be set in the environment (Vercel dashboard / local .env).
# If it is missing we fall back to a random key so the app still imports,
# but sessions will NOT survive restarts or work across serverless instances.
_secret_key = os.getenv("SECRET_KEY")
if not _secret_key:
    print("WARNING: SECRET_KEY is not set. Using a temporary random key.", file=sys.stderr)
    _secret_key = secrets.token_hex(32)
app.config['SECRET_KEY'] = _secret_key

Bootstrap5(app)

# ---------------------------- DATABASE ------------------------------------
class Base(DeclarativeBase):
    pass


def build_database_config(raw_url):
    """Return (uri, engine_options) for the given DATABASE_URL.

    - Postgres URLs are forced onto the pure-Python pg8000 driver, and any
      ?sslmode=... / channel_binding=... query string is dropped.
    - If DATABASE_URL is missing, fall back to a local SQLite file so the app
      still imports and runs locally.
    """
    if not raw_url:
        print("WARNING: DATABASE_URL is not set. Falling back to local SQLite.", file=sys.stderr)
        return "sqlite:///users.db", {}

    url = raw_url.strip().split("?")[0]
    for prefix in ("postgresql+psycopg2://", "postgresql+pg8000://", "postgresql://", "postgres://"):
        if url.startswith(prefix):
            url = "postgresql+pg8000://" + url[len(prefix):]
            break

    if url.startswith("postgresql+pg8000://"):
        return url, {
            "pool_pre_ping": True,
            "connect_args": {"ssl_context": True, "timeout": 15},
        }
    return url, {"pool_pre_ping": True}


db_url, engine_options = build_database_config(os.getenv("DATABASE_URL"))
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = engine_options

db = SQLAlchemy(model_class=Base)
db.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(250), nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)


# Create tables, but never let a temporary DB problem crash the import itself.
try:
    with app.app_context():
        db.create_all()
except Exception as exc:  # noqa: BLE001
    print(f"WARNING: could not create tables at startup: {exc}", file=sys.stderr)

# ---------------------------- LOG IN MANAGER ------------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ---------------------------- FORMS ------------------------------------
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

# ---------------------------- ROUTES ------------------------------------
@app.route("/")
def home():
    return render_template("index.html", user=current_user)

@app.route("/signup", methods=['POST', 'GET'])
def signup():
    signup_form = SignupForm()
    if signup_form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.name == signup_form.username.data)).scalar()
        if user:
            flash("Username taken. Try logging in.")
            return redirect(url_for('login'))
        email_taken = db.session.execute(db.select(User).where(User.email == signup_form.email.data)).scalar()
        if email_taken:
            flash("That email is already registered. Try logging in.")
            return redirect(url_for('login'))
        hashed = generate_password_hash(signup_form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(name=signup_form.username.data, email=signup_form.email.data, password=hashed)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("booking"))
    return render_template("signup.html", form=signup_form, user=current_user)

@app.route("/login", methods=['POST', 'GET'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.name == login_form.username.data)).scalar()
        if not user:
            flash("Account not found. Sign up instead")
            return redirect(url_for('signup'))
        if check_password_hash(user.password, login_form.password.data):
            login_user(user)
            return redirect(url_for("booking"))
        flash("Incorrect Password")
    return render_template("login.html", form=login_form, user=current_user)

@app.route("/booking")
@login_required
def booking():
    return render_template("booking.html", user=current_user)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))

# safepay system

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        # TODO: create SafePay payment, then redirect to SafePay's page
        return redirect(url_for('checkout'))
    return render_template('checkout.html', user=current_user)
    

@app.route('/safepay/webhook', methods=['POST'])
def safepay_webhook():
    data = request.json

    # Verify webhook signature here
    # Update order payment status in database

    return jsonify({"message": "Webhook received"}), 200

# -------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)

# TODO: 4. appointment card
# TODO: 5. if appointment verified, success page
# TODO: 6. if not verified, show wait page
# TODO: 7. get webhook url, to do this:
# TODO: 8. deploy on vercel, to do this:
