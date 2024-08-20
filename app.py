from flask import Flask, render_template, request, make_response
import mariadb
from dotenv import load_dotenv
import os
import json
import base64
from HMAC256 import hmac


load_dotenv()


def generate_jwt(username, admin):
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }
    payload = {
        "username": username,
        "admin": admin
    }

    encoded_header = base64.urlsafe_b64encode(
        json.dumps(header, separators=(',', ':')).encode('utf-8')).rstrip(b'=').decode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(',', ':')).encode('utf-8')).rstrip(b'=').decode("utf-8")
    signature = hmac(os.getenv("HS256"), f"{encoded_header}.{encoded_payload}")
    return signature


connection = mariadb.connect(
    host=f"{os.getenv("HOST_DB")}",
    user=f"{os.getenv("USER_DB")}",
    password=f"{os.getenv("PASSWORD")}",
    db=f"{os.getenv("DB")}"
)

cursor = connection.cursor()
cursor.execute("""CREATE TABLE IF NOT EXISTS User(
                username VARCHAR(15),
               password VARCHAR(128)
               )""")


cursor.execute("""CREATE TABLE IF NOT EXISTS Tokens(
                username VARCHAR(15),
               Token VARCHAR(256)
               )""")

app = Flask(__name__)


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        print(request.form["username"])
        print(request.form["password"])
        cursor.execute(f"""INSERT INTO User VALUES ('{
                       request.form['username']}', '{request.form['password']}'); """)
        user_token = generate_jwt(request.form['username'], "False")
        cursor.execute(f"""INSERT INTO Tokens VALUES ('{
                       request.form['username']}','{user_token}')""")
        connection.commit()
        return make_response("SignedUp")
    return render_template("signup.html")


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        if 'Authorization' in request.headers:
            username = request.args['username']
            if username:
                cursor.execute(
                    "SELECT Token FROM Tokens WHERE username = %s", (username,))
                result = cursor.fetchone()
                if result:
                    user_token = result[0]
                    if request.headers['Authorization'] == f"Bearer {user_token}":
                        return make_response("Success Already")

    if request.method == 'POST':
        cursor.execute(f"""SELECT password FROM User WHERE username = '{
                       request.form['username']}'""")
        result = cursor.fetchone()
        if result[0] == request.form['password']:
            response = make_response("Success")
            cursor.execute(f"""SELECT Token FROM Tokens WHERE username = '{
                request.form['username']}'""")
            user_token = cursor.fetchone()[0]
            response.headers['Authorization'] = f"Bearer {user_token}"
            return response
    return render_template("signup.html")
