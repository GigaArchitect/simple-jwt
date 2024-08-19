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
    sig = encoded_header + "." + encoded_payload
    print(sig, end=".")
    signature = hmac(os.getenv("HS256"), f"{encoded_header}.{encoded_payload}")
    print(signature)


generate_jwt("cc", "False")


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
        cursor = connection.cursor()
        cursor.execute(f"""INSERT INTO User VALUES ('{
                       request.args['username']}', '{request.args['password']}'); """)
        cursor.execute(f"""INSERT INTO Token VALUES ('{
                       request.args['username']}','token here')""")
        connection.commit()
    return render_template("signup.html")

# request header  ==> Authorization : Bearer <jwttoken>


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        cursor = connection.cursor()
        cursor.execute(f"""SELECT password FROM User WHERE username = '{
                       request.form['username']}'""")
        result = cursor.fetchone()
        if result[0] == request.form['password']:
            response = make_response("Success")
            response.headers['Authorization'] = "Bearer : Mustafa"
            return response
    return render_template("signup.html")
