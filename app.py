from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, send

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.secret_key = 'your_secret_key'
db = SQLAlchemy(app)
socketio = SocketIO(app) 

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f"Users {self.email}"

    def check_password(self, password):
        return check_password_hash(self.password, password)

@app.route("/")
def home():
    return render_template("welcomepage.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/support")
def support():
    return render_template("support.html")
@app.route("/search")
def search():
    return render_template("search.html")
@app.route("/chat")
def chat():
    if 'email' not in session:
        flash("You need to log in to access the chat.", "error")
        return redirect(url_for('login'))
    return render_template("chat.html", email=session['email'])

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form["email"]
        password = request.form["password"]
        user = Users.query.filter_by(email=email).first()

        if user is None:
            flash("Invalid Username! Make sure you are registered.", "error")
            return redirect(url_for('login'))

        if user.check_password(password):
            session['email'] = user.email
            flash("Login Successful!", "success")
            return redirect(url_for('chat'))
        else:
            flash("Invalid Password! Please try again.", "error")
            return redirect(url_for('login'))

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        existing_user = Users.query.filter_by(email=email).first()
        if existing_user:
            flash("This email is already registered. Please log in or use a different email.", "error")
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user = Users(email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for('login'))
    
    return render_template("signup.html")

@app.route("/logout")
def logout():
    session.clear() 
    flash("You have been logged out.", "success")
    return redirect(url_for('home'))  

@socketio.on('message')
def handle_message(msg):
    if 'email' in session:
        full_message = f"{session['email']}: {msg}"  
        print(f"Message: {full_message}")
        send(full_message, broadcast=True)  


if __name__ == "__main__":
    socketio.run(app, debug=True)
