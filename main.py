from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Float


app= Flask(__name__)

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

@app.route("/signup")
def signup():
    return 'signup'

@app.route("/login")
def login():
    return 'login'
# -------------------------------------------------------------------------
if __name__=="__main__":
    app.run(debug=True)

# TODO: 2. sign up
# TODO: 3. log in
# TODO: 4. appointment card
# TODO: 5. if appointment verified, success page 
# TODO: 6. if not verified, show wait page
