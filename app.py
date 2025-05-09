import os
from flask import Flask, flash, redirect, render_template, request, session, abort, url_for, get_flashed_messages
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
from functools import wraps
from datetime import datetime
from flask_font_awesome import FontAwesome

# Configure application
app = Flask(__name__)
font_awesome = FontAwesome(app)
app.secret_key = "flamingo"

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Connect to SQLite database
def get_db_connection():
    conn = sqlite3.connect("final-project.db")
    conn.row_factory = sqlite3.Row # to access columns by name
    return conn

# @app.after_request
# def after_request(response):
#     """Ensure responses aren't cached"""
#     response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
#     response.headers["Expires"] = 0
#     response.headers["Pragma"] = "no-cache"
#     return response

def login_required(f):
    @wraps(f)  
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
@login_required
def index():
        if session.get("role") == "user":
            return redirect("/user")
        elif session.get("role") == "admin":
            return redirect("/admin")

@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()
    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("login.html")
    # User reached route via POST (as by submitting a form via POST)
    else:
        username = request.form.get("username")
        password =  request.form.get("password")
        # Ensure username was submitted
        if not username:
            flash("must provide username", "danger")
            return render_template("/login.html")
        # Ensure password was submitted
        elif not password:
            flash("must provide password", "danger")
            return render_template("/login.html")
        # Query database for username and role
        try:
            conn = get_db_connection()
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            conn.close()
        except sqlite3.ProgrammingError as e:
            print("SQL Error: ", e)
        # Ensure username exists and password is correct
        if user and check_password_hash(user["hash"], password):
            # Remember which user has logged in
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["username"] = username

            # Redirect to admin dashboard or user dashboard
            #try if session["role"]
            if user["role"] == "admin":
                return redirect("/admin")
            else:
                return redirect("/user")
        else:
            flash("invalid username and/or password", "danger")
            return render_template("login.html")


@app.route("/logout")
def logout():
    # Forget any user_id
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("/register.html")
    # User reached route via POST (as by submitting a form via POST)
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirmation")
        role = request.form.get("role", "user")
        admin_key = request.form.get("admin_key")
        # Ensure username was submitted
        if not username:
            flash("must provide username", "danger")
            return render_template("/register.html")
        # Ensure password was submitted
        elif not password:
            flash("must provide password", "danger")
            return render_template("/register.html")
        # Ensure password confirmation was submitted
        elif not confirm:
            flash("must confirm password", "danger")
            return render_template("/register.html")
        # Ensure password confirmation matches password
        elif not confirm == password:
            flash("password confirmation must match password", "danger")
            return render_template("/register.html")
        # Ensure admin key is valid
        elif role == "admin" and not admin_key == app.secret_key:
            flash("invalid admin key", "danger")
            return render_template("/register.html")
        # query database to see if username already exists
        try:
            conn = get_db_connection()
            name = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
            conn.close()
        except sqlite3.ProgrammingError as e:
            print("SQL Error: ", e)
        # If username does not already exist, insert into the database
        if not name:
            hash = generate_password_hash(password, method='scrypt', salt_length=16)
            try:
                conn = get_db_connection()
                conn.execute("INSERT INTO users (username, hash, role) VALUES(?, ?, ?)", (username, hash, role))
                conn.commit()
                conn.close()
            except sqlite3.ProgrammingError as e:
                print("SQL Error: ", e)
            # Redirect to admin dashboard or user dashboard
            if role == "admin":
                return redirect("/admin")
            else:
                return redirect("/user")
        else:
            flash("username already exists, please try a new username", "danger")
            return render_template("/register.html")


@app.route("/admin")
@admin_required
@login_required
def admin():
    # Query database for the children that the administrator oversees
    try:
        conn = get_db_connection()
        children = conn.execute("SELECT user_id FROM administrators WHERE admin_id = ?", (session["user_id"],)).fetchall()
        conn.close()
    except sqlite3.ProgrammingError as e:
        print("SQL Error: ", e)
    # Loop through the children, create a table row for each child
    table_data = ""
    for child in children:
        try:
            conn = get_db_connection()
            user = conn.execute("SELECT * FROM users WHERE id = ?", (child["user_id"],)).fetchone()
            conn.close()
        except sqlite3.ProgrammingError as e:
            print("SQL Error: ", e)
        cash = f"${user["cash"]: .2f}"
        table_row = f"""
            <tr>
                <td class="text-start">{user['username']}</td>
                <td class="text-end">{cash}</td>
                <td class="text-end">
                    <form action="/confirm_deposit" method="POST">
                        <input type="hidden" name="id" value={user['id']}>
                        <button class="btn btn-primary"><i class="fa-solid fa-plus"></i></button>
                    </form>
                </td>
                <td class="text-end">
                    <form action="/confirm_withdraw" method="POST">
                        <input type="hidden" name="id" value={user['id']}>
                        <button class="btn btn-primary"><i class="fa-solid fa-minus"></i></button>
                    </form>
                </td>
                <td class="text-end">
                    <form action="/history" method="POST">
                        <input type="hidden" name="id" value={user['id']}>
                        <input type="hidden" name="name" value={user['username']}>
                        <button class="btn btn-primary"><i class="fa-solid fa-list-ul"></i></button>
                    </form>
                </td>
                <td class="text-end">
                    <form action="/confirm_delete" method="POST">
                        <input type="hidden" name="id" value={user['id']}>
                        <button class="btn btn-primary"><i class="fa-solid fa-trash-can"></i></button>
                    </form>
                </td>
            </tr>"""
        table_data += table_row
    return render_template("/admin.html", table_data=table_data, admin_name=session["username"])


@app.route("/add", methods=["GET", "POST"])
@admin_required
@login_required
def add():
    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("add.html")
    # User reached route via POST (as by submitting a form via POST)
    else:
        action = request.form.get("action")
        if action == "cancel":
            return redirect ("/admin")
        elif action == "add":
            # Ensure child name was submitted
            child_name = request.form.get("childname")
            if not child_name:
                flash("must enter a name", "danger")
                return render_template("/add.html")
            # Query database for the child
            try:
                conn = get_db_connection()
                child = conn.execute(
                    "SELECT * FROM users WHERE username = ?", (child_name,)
                ).fetchone()
                conn.close()
            except sqlite3.ProgrammingError as e:
                print("SQL Error: ", e)
            # If the child is in the database and is not registered as admin,
            # instert child into the administrators table
            if child and not child["role"] == "admin":
                try:
                    conn = get_db_connection()
                    conn.execute("INSERT INTO administrators (admin_id, user_id) VALUES (?, ?)", (session["user_id"], child["id"]))
                    conn.commit()
                    conn.close()
                except sqlite3.ProgrammingError as e:
                    print("SQL Error: ", e)
            else:
                flash("must enter a registered username", "danger")
                return render_template("/add.html")
            return redirect ("/admin")


@app.route("/confirm_deposit", methods=["GET", "POST"])
@admin_required
@login_required
def confirm_deposit():
    # User reached route via POST 
    if request.method == "POST":
        child_id = request.form.get("id")
        # Query database for the child
        try:
            conn = get_db_connection()
            child = conn.execute(
                "SELECT * FROM users WHERE id = ?", (child_id,)
            ).fetchone()
            conn.close()
        except sqlite3.ProgrammingError as e:
            print("SQL Error: ", e)
        return render_template ("/confirm_deposit.html", child=child)
    

@app.route("/deposit", methods=["GET", "POST"])
@admin_required
@login_required
def deposit():
    # User reached route via POST 
    if request.method == "POST":
        action = request.form.get("action")
        if action == "cancel":
            return redirect ("/admin")
        elif action == "deposit":
            child_id = request.form.get("id")
            deposit = request.form.get("deposit")
            comment = request.form.get("comment")
            # Query database for the child
            try:
                conn = get_db_connection()
                child = conn.execute("SELECT * FROM users WHERE id = ?", (child_id,)).fetchone()
                conn.close()
            except sqlite3.ProgrammingError as e:
                print("SQL Error: ", e)
            current_cash = child["cash"]
            try:
                deposit = round(float(deposit), 2)
            except ValueError:
                flash("must enter a number", "danger")
                return render_template("/confirm_deposit.html", child=child)
            if not deposit or deposit <= 0:
                flash("must enter a number greater than 0", "danger")
                return render_template("/confirm_deposit.html", child=child)
            # Query database to make the deposit
            try:
                conn = get_db_connection()
                conn.execute("INSERT INTO transactions (user_id, date, comment, action, balance) VALUES (?, ?, ?, ?, ?)", 
                            (child_id, datetime.now(), comment, deposit, current_cash + deposit))
                conn.execute("UPDATE users SET cash = cash + ? WHERE id = ?", (deposit, child_id))
                conn.commit()
                conn.close()
            except sqlite3.ProgrammingError as e:
                print("SQL Error: ", e)
    return redirect ("/admin")


@app.route("/confirm_withdraw", methods=["GET", "POST"])
@admin_required
@login_required
def confirm_withdraw():
    # User reached route via POST 
    if request.method == "POST":
        child_id = request.form.get("id")
        # Query database for the child
        try:
            conn = get_db_connection()
            child = conn.execute(
                "SELECT * FROM users WHERE id = ?", (child_id,)
            ).fetchone()
            conn.close()
        except sqlite3.ProgrammingError as e:
            print("SQL Error: ", e)
        return render_template ("/confirm_withdraw.html", child=child)


@app.route("/withdraw", methods=["GET", "POST"])
@admin_required
@login_required
def withdraw():
    # User reached route via POST 
    if request.method == "POST":
        action = request.form.get("action")
        if action == "cancel":
            return redirect ("/admin")
        elif action == "withdraw":
            child_id = request.form.get("id")
            withdraw = request.form.get("withdraw")
            comment = request.form.get("comment")
            # Query database for the child
            try:
                conn = get_db_connection()
                child = conn.execute("SELECT * FROM users WHERE id = ?", (child_id,)).fetchone()
                conn.close()
            except sqlite3.ProgrammingError as e:
                print("SQL Error: ", e)
            current_cash = child["cash"]
            try:
                withdraw = -abs(round(float(withdraw), 2))
            except ValueError:
                flash("must enter a number", "danger")
                return render_template("/confirm_withdraw.html", child=child)
            if not withdraw:
                flash("must enter a number", "danger")
                return render_template("/confirm_withdraw.html", child=child)
            # Query database to make the withraw
            try:
                conn = get_db_connection()
                conn.execute("INSERT INTO transactions (user_id, date, comment, action, balance) VALUES (?, ?, ?, ?, ?)", 
                            (child_id, datetime.now(), comment, withdraw, current_cash + withdraw))
                conn.execute("UPDATE users SET cash = cash + ? WHERE id = ?", (withdraw, child_id))
                conn.commit()
                conn.close()
            except sqlite3.ProgrammingError as e:
                print("SQL Error: ", e)
    return redirect ("/admin")


@app.route("/confirm_delete", methods=["GET", "POST"])
@admin_required
@login_required
def confirm_delete():
    # User reached route via POST 
    if request.method == "POST":
        child_id = request.form.get("id")
        # Query database for the child
        try:
            conn = get_db_connection()
            child = conn.execute(
                "SELECT * FROM users WHERE id = ?", (child_id,)
            ).fetchone()
            conn.close()
        except sqlite3.ProgrammingError as e:
            print("SQL Error: ", e)
        return render_template ("/confirm_delete.html", child=child)


@app.route("/delete", methods=["GET", "POST"])
@admin_required
@login_required
def delete():
    # User reached route via POST 
    if request.method == "POST":
        action = request.form.get("action")
        if action == "cancel":
            return redirect ("/admin")
        elif action == "delete":
            child_id = request.form.get("id")
            # Query database for the child
            try:
                conn = get_db_connection()
                conn.execute("DELETE FROM administrators WHERE admin_id = ? AND user_id = ?", (session["user_id"], child_id))
                conn.commit()
                conn.close()
            except sqlite3.ProgrammingError as e:
                print("SQL Error: ", e)
    return redirect ("/admin")

@app.route("/history", methods=["GET", "POST"])
@login_required
def history():
    if request.method == "POST":
        child_id = request.form.get("id")
        name = request.form.get("name")
        # Query database for the child's transactions
        try:
            conn = get_db_connection()
            transactions = conn.execute("SELECT date, comment, action, balance FROM transactions WHERE user_id = ?", (child_id,)).fetchall()
            conn.close()
        except sqlite3.ProgrammingError as e:
            print("SQL Error: ", e)
        table_data = ""
        for transaction in transactions:
            date = datetime.strptime(transaction["date"], "%Y-%m-%d %H:%M:%S.%f")
            formatted_date = date.strftime("%m-%d-%Y")
            action = f"${transaction["action"]: .2f}"
            balance = f"${transaction["balance"]: .2f}"
            table_row = f"""
            <tr>
                <td class="text-start">{formatted_date}</td>
                <td class="text-end">{action}</td>
                <td class="text-end">{transaction["comment"]}</td>
                <td class="text-end">{balance}</td>
            </tr>"""
            table_data += table_row
        return render_template("/history.html", table_data=table_data, name=name)

@app.route("/user")
@login_required
def user():
    #Query database for user info
    try:
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        conn.close()
    except sqlite3.ProgrammingError as e:
            print("SQL Error: ", e)
    cash = f"${user["cash"]: .2f}"
    return render_template("/user.html", name=user["username"], id=user["id"], cash=cash)





