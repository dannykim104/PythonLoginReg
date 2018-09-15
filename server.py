from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import os, binascii
import re 
import md5

DIG_REGEX = re.compile(r".*[0-9].*")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$")

app = Flask(__name__)
app.secret_key="Keepthissecret"

mysql = MySQLConnector(app,'registrationdb')


@app.route('/')
def default():

    return render_template('index.html')

@app.route('/login', methods=['POST'])
def validate():
    validate = True
    if len(request.form["email"]) < 1:
        flash("Email must not be blank!", "login")
        validate = False

    elif not EMAIL_REGEX.match(request.form["email"]):
        flash("Invalid email!", "login")
        validate = False

    if len(request.form["password"]) < 1:
        flash("Password must not be blank!", "login")
        validate = False

    if valid:
        query = "SELECT id, password, salt FROM users WHERE email = :email"
        data = {"email": request.form["email"]}
        pw_info = mysql.query_db(query, data)
        if pw_info == []:
            flash("Email not registered!", "login")
            return redirect("/")
        elif md5.new(request.form["password"]+pw_info[0]["salt"]).hexdigest() == pw_info[0]["password"]:
            session["id"]=pw_info[0]["id"]
            flash("Successfully logged in!")
            return redirect("/success")
        else:
            flash("Email and password do not match!", "login")

    return redirect("/")



@app.route('/registration', methods=['POST'])
def valid():
    valid = True 

    if len(request.form['first_name']) < 1:
       flash("First name cannot be empty")
       valid = False 

    elif len(request.form['first_name']) < 2:
       flash("First name must be at least 2 chars")
       valid = False

    elif DIG_REGEX.match(request.form['first_name']):
        flash("First name cannot contain digits")
        valid = False 


    if len(request.form['last_name']) < 1:
       flash("Last name cannot be empty")
       valid = False 

    elif len(request.form['last_name']) < 2:
       flash("Last name must be at least 2 chars")
       valid = False

    elif DIG_REGEX.match(request.form['last_name']):
        flash("Last name cannot contain digits")
        valid = False 

    if len(request.form['email']) < 1:
       flash("Email cannot be empty")
       valid = False 
    
    elif not EMAIL_REGEX.match(request.form["email"]):
        flash("Invalid email!", "registration")
        valid = False

    else:
        query = "SELECT email FROM users WHERE email = :email"
        data = {"email":request.form["email"]}
        if mysql.query_db(query, data) != []:
            flash("An account with that email is already registered!", "registration")
            valid = False

    if len(request.form['password']) < 1:
       flash("Password cannot be empty")
       valid = False 

    elif len(request.form['password']) < 8:
       flash("Password must be at least 8 chars")
       valid = False

    if len(request.form["password_confirm"]) < 1:
        flash("Password confirmation cannot be blank!", "registration")
        valid = False

    elif request.form["password"] != request.form["password_confirm"]:
        flash("Password confirmation must match password!", "registration")
        valid = False

    if valid:
        salt = binascii.b2a_hex(os.urandom(15))
        hashed_password = md5.new(request.form["password"] + salt).hexdigest()
        query = "INSERT INTO users (first_name, last_name, email, password, salt, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, :salt, NOW(), NOW())"
        data = {
            "first_name": request.form["first_name"],
            "last_name": request.form["last_name"],
            "email": request.form["email"],
            "password": hashed_password,
            "salt": salt
        }
        session["id"] = mysql.query_db(query, data)
        flash("Successfully registered and logged in!")
        return redirect("/success")
    else:
        return redirect("/")

    return redirect('/')

@app.route('/success')
def success():
    query = "SELECT first_name, last_name FROM users WHERE id = :id"
    data = {"id": session["id"]}
    namedic = mysql.query_db(query, data)
    name = namedic[0]["first_name"]+" "+namedic[0]["last_name"]
    return render_template("success.html", user=name)

@app.route("/logout", methods=["POST"])
def logout():
    session.pop("id")
    return redirect("/")


app.run(debug=True)
