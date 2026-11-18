from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, inspect, text
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
import requests
from safepay_python.resources.payments import Payments
from safepay_python.utils.builder import build_api_url

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


SAFEPAY_ENV = "sandbox"


def get_safepay():
    return Safepay({
        "environment": SAFEPAY_ENV,
        "apiKey": os.getenv("API_KEY"),
        "v1Secret": os.getenv("SAFEPAY_API_KEY"),
        "webhookSecret": os.getenv("WEBHOOK_SECRET"),
    })

APPOINTMENT_FEE = 100  # PKR

# TRACKER_ENDED is the state Safepay's own docs show on a paid tracker.
PAID_STATES = {"PAID", "PAYMENT_SUCCESS", "SUCCESS", "SUCCEEDED", "COMPLETED", "TRACKER_ENDED"}


def fetch_tracker(tracker):
    """Ask Safepay directly about a tracker. Returns its data dict, or None if it can't be fetched.

    This is the authoritative answer to "was this really paid?" and does not
    depend on the redirect's query string or on which secret is configured.
    """
    token = tracker if tracker.startswith("track_") else f"track_{tracker}"
    url = f"{build_api_url(SAFEPAY_ENV)}/reporter/api/v1/payments/{token}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json().get("data")
    except Exception as exc:  # noqa: BLE001
        app.logger.error("Could not fetch Safepay tracker %s: %s", token, exc)
        return None


def tracker_is_paid(info):
    return bool(info) and str(info.get("state", "")).upper() in PAID_STATES


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
        # The library signs body["data"], so it must receive the whole parsed
        # request body (which has a "data" key), not a dict wrapping it again.
        return get_safepay().is_webhook_valid(
            {"x-sfpy-signature": signature},
            data
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
        # Safepay tracker metadata looks like {"order_id": {"key": "order_id", "value": "..."}}
        if obj.get("key") in keys and isinstance(obj.get("value"), str) and obj["value"]:
            return obj["value"]
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

def sync_appointment_table():
    """Bring an already-existing `appointment` table in line with the model.

    db.create_all() only creates MISSING tables; it never alters existing ones.
    If the table was created by an older version of this app, it can lack the
    current columns (e.g. appt_id) or still have old NOT NULL columns (e.g.
    order_id) that we no longer fill in, and every INSERT then fails.
    This only ADDS missing columns and RELAXES leftover NOT NULL constraints;
    it never drops columns or deletes data.
    """
    insp = inspect(db.engine)
    if not insp.has_table("appointment"):
        return

    existing = {col["name"]: col for col in insp.get_columns("appointment")}
    model_cols = {col.name: col for col in Appointment.__table__.columns}
    is_postgres = db.engine.dialect.name == "postgresql"

    with db.engine.begin() as conn:
        for name, col in model_cols.items():
            if name not in existing and not col.primary_key:
                col_type = col.type.compile(dialect=db.engine.dialect)
                conn.execute(text(f'ALTER TABLE appointment ADD COLUMN "{name}" {col_type}'))
                print(f"INFO: added missing column appointment.{name}", file=sys.stderr)

        # Old columns the app no longer writes must not block inserts. This also
        # covers columns we DO have but that an older version made NOT NULL
        # (e.g. tracker, which is only known after payment).
        if is_postgres:
            for name, col in existing.items():
                if col["nullable"] or name == "id":
                    continue
                model_col = model_cols.get(name)
                if model_col is None or model_col.nullable:
                    conn.execute(text(f'ALTER TABLE appointment ALTER COLUMN "{name}" DROP NOT NULL'))
                    print(f"INFO: made appointment.{name} nullable", file=sys.stderr)

    # appt_id is how redirects/webhooks find a row, so keep it unique.
    try:
        with db.engine.begin() as conn:
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_appointment_appt_id ON appointment (appt_id)"
            ))
    except Exception as exc:  # noqa: BLE001
        print(f"WARNING: could not add unique index on appointment.appt_id: {exc}", file=sys.stderr)


# Create tables, but never let a temporary DB problem crash the import itself.
try:
    with app.app_context():
        db.create_all()
        sync_appointment_table()
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

def save_pending_appointment(appt_id):
    """Insert the pending appointment row. Returns None on success, else the exception.

    The startup schema repair can silently fail on serverless cold starts, so if
    the first insert fails we run the repair again and retry once.
    """
    last_exc = None
    for attempt in (1, 2):
        try:
            db.session.add(Appointment(user_id=current_user.id, appt_id=appt_id,
                                       amount=APPOINTMENT_FEE, status="pending"))
            db.session.commit()
            return None
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            last_exc = exc
            app.logger.exception("Saving pending appointment failed (attempt %s): %s", attempt, exc)
            if attempt == 1:
                try:
                    sync_appointment_table()
                except Exception as sync_exc:  # noqa: BLE001
                    app.logger.error("Schema repair failed: %s", sync_exc)
    return last_exc


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
        save_error = save_pending_appointment(appt_id)
        if save_error is not None:
            flash(f"Couldn't save your appointment ({type(save_error).__name__}). Please try again.")
            return redirect(url_for('checkout'))
        # Backup for when Safepay's redirect doesn't carry our order id back.
        session["pending_appt_id"] = appt_id

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


@app.route('/payment/success', methods=['GET', 'POST'])
def payment_success():
    """Safepay sends the customer here after a successful payment.

    Deliberately NOT @login_required: the customer's login cookie can be lost on
    the way back from Safepay (e.g. SECRET_KEY unset on serverless, or a
    cross-site POST), and that used to mean the payment was never recorded.
    The payment itself is proven by Safepay, not by our session:
      1. `sig` is a valid HMAC of the tracker with our secret, or
      2. Safepay itself reports the tracker as paid.
    Which appointment it belongs to comes from what Safepay recorded against
    the tracker. Only if that is unavailable do we fall back to the redirect's
    order_id / our session, and then only for a logged-in owner.
    """
    args = request.values  # query string and form body (Safepay may use either)
    app.logger.info("Safepay redirect (%s): %r | logged_in=%s",
                    request.method, dict(args), current_user.is_authenticated)
    sig = args.get("sig")
    tracker = args.get("tracker")
    order_id = args.get("order_id") or args.get("orderId")
    if not tracker:
        flash("We couldn't confirm your payment: no payment reference came back from Safepay. "
              "If you were charged, please contact us.")
        return redirect(url_for('checkout'))

    secret_cfg = {k: bool(os.getenv(k)) for k in ("API_KEY", "SAFEPAY_API_KEY", "WEBHOOK_SECRET")}
    if os.getenv("SAFEPAY_API_KEY") and os.getenv("SAFEPAY_API_KEY") == os.getenv("API_KEY"):
        app.logger.warning("SAFEPAY_API_KEY equals API_KEY: the v1 secret is probably the public key.")

    signature_ok = False
    if sig:
        try:
            signature_ok = get_safepay().is_signature_valid({"sig": sig, "tracker": tracker})
        except Exception as exc:  # noqa: BLE001
            app.logger.error("Safepay signature check failed: %s", exc)

    tracker_info = fetch_tracker(tracker)
    paid_by_safepay = tracker_is_paid(tracker_info)
    app.logger.info("Payment check: signature_ok=%s tracker_state=%r paid_by_safepay=%s env_set=%s",
                    signature_ok, (tracker_info or {}).get("state"), paid_by_safepay, secret_cfg)
    if not (signature_ok or paid_by_safepay):
        flash("Payment could not be verified.")
        return redirect(url_for('checkout'))

    proven_order_id = find_value((tracker_info or {}).get("metadata"), ("order_id", "orderId"))
    authed = current_user.is_authenticated
    if not proven_order_id and not authed:
        flash("Your payment went through. Please log in to finish confirming your appointment.")
        return redirect(url_for('login'))

    order_id = proven_order_id or order_id or session.get("pending_appt_id")
    query = db.select(Appointment)
    if order_id:
        query = query.where(Appointment.appt_id == order_id)
    else:
        # Last resort (logged-in only here): this user's newest unpaid appointment.
        query = (query.where(Appointment.user_id == current_user.id, Appointment.status == "pending")
                 .order_by(Appointment.id.desc()))
    appt = db.session.execute(query).scalars().first()
    if not appt:
        app.logger.error("No appointment found for order_id=%r tracker=%s", order_id, tracker)
        flash("We couldn't find that appointment.")
        return redirect(url_for('booking'))
    if not proven_order_id and appt.user_id != current_user.id:
        flash("That payment belongs to a different appointment.")
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
            app.logger.info("Appointment %s marked paid (tracker %s)", appt.appt_id, tracker)
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            app.logger.exception("Could not mark appointment paid: %s", exc)
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

    # Some payloads carry only the tracker; ask Safepay which order it belongs to.
    if is_paid and tracker and not order_id:
        order_id = find_value((fetch_tracker(tracker) or {}).get("metadata"), ("order_id", "orderId"))

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
