from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Float
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Length
import os
from flask_bootstrap import Bootstrap5
from dotenv import load_dotenv
load_dotenv()

app= Flask(__name__)

# ---------------------------- FORMS ------------------------------------
app.config['WTF_CSRF_TIME_LIMIT'] = None  
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
Bootstrap5(app)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

# ---------------------------- DATABASE ------------------------------------
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///users.db"
db = SQLAlchemy(model_class=Base)
db.init_app(app)

class User(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(250), nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)


with app.app_context():
    db.create_all()
# ---------------------------- ROUTES ------------------------------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/signup", methods= ['POST','GET'])
def signup():
    signup_form= SignupForm()
    return render_template("signup.html", form= signup_form)

@app.route("/login", methods= ['POST','GET'])
def login():
    login_form=LoginForm()
    return render_template("login.html",form= login_form)
# -------------------------------------------------------------------------
if __name__=="__main__":
    app.run(debug=True)

# TODO: 2. sign up
# TODO: 3. log in
# TODO: 4. appointment card
# TODO: 5. if appointment verified, success page 
# TODO: 6. if not verified, show wait page
