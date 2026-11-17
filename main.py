from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Length
import os
import sys
import hmac
import hashlib
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_bootstrap import Bootstrap5
from dotenv import load_dotenv
from safepay_python.safepay import Safepay
import asyncio
from safepay_python.resources.payments import Payments

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

# ---------------------------- PAYMENTS  ------------------------------------


def get_safepay():
    return Safepay({
        "environment": "sandbox",
        "apiKey": os.getenv("API_KEY"),
        "v1Secret": os.getenv("SAFEPAY_API_KEY"),
        "webhookSecret": os.getenv("WEBHOOK_SECRET"),
    })

APPOINTMENT_FEE = 100  # PKR

PAID_STATES = {"PAID", "PAYMENT_SUCCESS", "SUCCESS", "SUCCEEDED", "COMPLETED"}


def verify_payment(signature, raw_body, data):
    """Check the X-SFPY-SIGNATURE header of a webhook call.

    Safepay signs the request body with HMAC-SHA512 using the webhook secret.
    We first check the exact raw bytes we received (most reliable), then fall
    back to the library's check (which re-serialises the parsed JSON).
    """
    secret = os.getenv("WEBHOOK_SECRET")
    if not secret:
        app.logger.error("WEBHOOK_SECRET is not set; cannot verify webhook.")
        return False

    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
    if hmac.compare_digest(expected, signature):
        return True

    try:
        return get_safepay().is_webhook_valid(
            {"x-sfpy-signature": signature},
            {"data": data}
        )
    except Exception as exc:  # noqa: BLE001
        app.logger.error("Webhook signature check failed: %s", exc)
        return False


def find_value(obj, keys):
    """Return the first string value stored under any of `keys`, searching nested dicts/lists."""
    if isinstance(obj, dict):
        for key in keys:
            value = obj.get(key)
            if isinstance(value, str) and value:
                return value
        for value in obj.values():
            found = find_value(value, keys)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = find_value(item, keys)
            if found:
                return found
    return None


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

class Appointment(db.Model):
    __tablename__ = "appointment"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # appt_id is the order id we hand to Safepay, so redirects/webhooks can find this row.
    appt_id = db.Column(db.String(100), unique=True, index=True)
    # Safepay tracker id, filled in once the payment is confirmed.
    tracker = db.Column(db.String(200))
    amount = db.Column(db.Integer)
    status = db.Column(db.String(20), default="pending")

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

# ------------------------------- SAFEPAY ROUTES ------------------------------------------


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if request.method == 'POST':
        sp = get_safepay()
        try:
            resp = asyncio.run(Payments(sp.config).create_payment(
                {"amount": APPOINTMENT_FEE, "currency": "PKR"}
            ))
            token = resp["data"]["token"]
        except Exception as exc:
            app.logger.error("Safepay init failed: %s | response=%r", exc, locals().get("resp"))
            flash("Couldn't start the payment. Please try again.")
            return redirect(url_for('checkout'))

        # One id, used both as our appointment reference and as Safepay's order_id,
        # so the redirect and the webhook can find this exact row later.
        appt_id = f"APPOINTMENT_{current_user.id}_{secrets.token_hex(4)}"
        try:
            db.session.add(Appointment(user_id=current_user.id, appt_id=appt_id,
                                       amount=APPOINTMENT_FEE, status="pending"))
            db.session.commit()
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            app.logger.error("Could not save pending appointment: %s", exc)
            flash("Couldn't save your appointment. Please try again.")
            return redirect(url_for('checkout'))

        url = sp.get_checkout_url({
            "beacon": token,
            "orderId": appt_id,
            "redirectUrl": url_for('payment_success', _external=True),
            "cancelUrl": url_for('checkout', _external=True),
            "source": "custom",
            "webhooks": True,
        })
        return redirect(url)
    return render_template('checkout.html', user=current_user)


@app.route('/payment/success')
@login_required
def payment_success():
    """Safepay sends the customer here after a successful payment.

    The redirect carries `sig` (HMAC of the tracker, signed with our shared
    secret), `tracker` and `order_id`. We verify the signature, mark the
    appointment as paid, then send the customer to the appointment page.
    """
    sig = request.args.get("sig")
    tracker = request.args.get("tracker")
    order_id = request.args.get("order_id")
    if not (sig and tracker and order_id):
        flash("We couldn't confirm your payment. Please try again.")
        return redirect(url_for('checkout'))

    try:
        signature_ok = get_safepay().is_signature_valid({"sig": sig, "tracker": tracker})
    except Exception as exc:  # noqa: BLE001
        app.logger.error("Safepay signature check failed: %s", exc)
        signature_ok = False
    if not signature_ok:
        flash("Payment could not be verified.")
        return redirect(url_for('checkout'))

    appt = db.session.execute(
        db.select(Appointment).where(
            Appointment.appt_id == order_id,
            Appointment.user_id == current_user.id,
        )
    ).scalar()
    if not appt:
        flash("We couldn't find that appointment.")
        return redirect(url_for('booking'))

    if appt.status != "paid":
        # A tracker proves ONE payment, so it can only confirm ONE appointment.
        already_used = db.session.execute(
            db.select(Appointment).where(
                Appointment.tracker == tracker, Appointment.id != appt.id
            )
        ).scalar()
        if already_used:
            flash("That payment was already used for another appointment.")
            return redirect(url_for('booking'))
        try:
            appt.status = "paid"
            appt.tracker = tracker
            db.session.commit()
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            app.logger.error("Could not mark appointment paid: %s", exc)
            flash("Payment received, but we couldn't save it. Please contact us.")
            return redirect(url_for('booking'))

    return redirect(url_for('appointment'))


@app.route('/appointment')
@login_required
def appointment():
    appt = db.session.execute(
        db.select(Appointment)
        .where(Appointment.user_id == current_user.id, Appointment.status == "paid")
        .order_by(Appointment.id.desc())
    ).scalars().first()
    if not appt:
        flash("You don't have a confirmed appointment yet.")
        return redirect(url_for('booking'))
    return render_template("appointment.html", user=current_user, appt=appt)


@app.route('/safepay/webhook', methods=['POST'])
def safepay_webhook():
    """Server-to-server backup: marks the appointment paid even if the customer
    closes the browser before the redirect above happens."""
    signature = request.headers.get('X-SFPY-SIGNATURE')
    if not signature:
        return jsonify({"error": "Missing signature"}), 400

    raw_body = request.get_data()
    data = request.get_json(silent=True) or {}
    if not verify_payment(signature, raw_body, data):
        return jsonify({"error": "Invalid signature"}), 400

    app.logger.info("Safepay webhook payload: %r", data)  # inspect real shape

    order_id = find_value(data, ("order_id", "orderId"))
    tracker = find_value(data, ("tracker",))
    state = (find_value(data, ("state", "status")) or "").upper()
    event = (find_value(data, ("type", "event")) or "").lower()
    is_paid = state in PAID_STATES or "succe" in event or "paid" in event

    if order_id and is_paid:
        appt = db.session.execute(
            db.select(Appointment).where(Appointment.appt_id == order_id)
        ).scalar()
        if appt and appt.status != "paid":
            try:
                appt.status = "paid"
                if tracker:
                    appt.tracker = tracker
                db.session.commit()
            except Exception as exc:  # noqa: BLE001
                db.session.rollback()
                app.logger.error("Webhook could not update appointment: %s", exc)
                return jsonify({"error": "db error"}), 500

    return jsonify({"message": "ok"}), 200

# -------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
