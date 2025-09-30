from flask import Flask, request, jsonify, render_template
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required,get_jwt_identity
import mysql.connector

app = Flask(__name__)
bcrypt = Bcrypt(app)

#secret key para sa JWT
app.config["GALING_TANGINA"] = "supersecretkey"
jwt = JWTManager(app)

# Database natin
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        port="3306",
        database="StandBy Muna Sa Pangalan"
    )

# for registration. diko pa alam kung gagana HAHAHA fak
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get("username")
    email = request.json.get("email")

    if username in users:
        return render_template('register.html', alert="Username already exists!", alert_type="danger")
    
    password = request.json.get("password")
    confirm_password = request.json.get("confirm_password")

    if password != confirm_password:
        return render_template('register.html', alert="Passwords do not match!", alert_type="danger")
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
    db.commit()
    cursor.close()
    return render_template('register.html', alert="Registration successful!", alert_type="success")

@app.route('/login', methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    #if mali yung username
    if username not in users:
        return render_template('login.html', alert="Invalid username or password!", alert_type="danger")
    
    #if mali yung password
    if not bcrypt.check_password_hash(users[username], password):
        return render_template('login.html', alert="Invalid username or password!", alert_type="danger")

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

#Protected route para kapag nagbigay si user ng tamang information,
#mabibigyan siya ng access token para makuha niya yung protected data niya
#galing tangina
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200