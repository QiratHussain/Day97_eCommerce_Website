from flask import Flask, render_template, redirect, url_for

app= Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")


if __name__=="__main__":
    app.run(debug=True)

# TODO: 1. homepage
# TODO: 2. sign up
# TODO: 3. log in
# TODO: 4. appointment card
# TODO: 5. if appointment verified, success page 
# TODO: 6. if not verified, show wait page
