#This module provides a portable way of using operating system dependent functionality
import os

#Import the connection to a database
import sqlite3

#Import Flask modules to create web applications
from sqlite3.dbapi2 import Cursor

from flask import Flask, flash, jsonify, redirect, render_template, request, session
#Allows the use of a sessions which allows you to store information specific to a user
from flask_session import Session

#Creates a temporary directory in the most secure manner possible
from tempfile import mkdtemp

#Werkzeug is python library which contains lot of development and debugging tools for implementation of web application
#This module implements a number of Python exceptions you can raise from within your views to trigger a standard non-200 response
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
#This module allows to generate and check hash passwords
from werkzeug.security import check_password_hash, generate_password_hash

#Import all functions from the helpers.py file
from helpers import apology, login_required, lookup, usd

# Configure your .py file as a Flask web app
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate" # HTTP 1.1.
    response.headers["Expires"] = 0 #HTTP 1.0.
    response.headers["Pragma"] = "no-cache" #Proxies
    return response

# Custom filter, will make it easier to format values as US dollars (USD)
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Create a connection with the database
conn = sqlite3.connect('finance.db', check_same_thread=False)
db = conn.cursor()

#An APY_KEY is need it to connect to the API (https://iexcloud.io/)
if not os.environ.get("API_KEY", "pk_bed6a595932e44698d5f80fd2c622993"):
    raise RuntimeError("API_KEY not set")

@app.route("/")
@login_required #This decorator ensures that, if a user tries to visit any of those routes, it will first be redirected to login
def index():
    """Show portfolio of stocks"""

    user = session["user_id"]

    # Collect the data of the user
    db.execute("SELECT symbol, name, SUM(shares) as total_shares FROM purchase WHERE id_user = ? GROUP BY symbol HAVING total_shares > 0", (user,))
    rows = db.fetchall()
    db.execute("SELECT cash FROM users WHERE id =?", (user,))
    cash = db.fetchone()

    # If new user, no info to display
    if len(rows) == 0:
        return render_template("index.html", total=10000, cash_remaining=10000)

    else:
        balance = 0
        quotes = {}
        for row in rows:
            # Store price of share up to date
            quotes[row[0]] = lookup(row[0])

            # Calculate Total CASH
            quote = lookup(row[0])
            price = quote.get("price")
            shares = row[2]
            sub_total = shares * price
            balance += sub_total

        cash_remaining = cash[0]
        total = cash_remaining + balance

        return render_template("index.html", quotes=quotes, rows=rows, total=total, cash_remaining=cash_remaining)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    user = session["user_id"]
    if request.method == "POST":
        s = request.form.get("symbol")
        symbol = s.upper()

        # Ensure a symbol was submitted
        quotes = lookup(symbol)
        if not symbol or quotes == None:
            return apology("Must provide a Valid Symbol", 403)

        # Ensure is a positive intenger
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Must provide a positive integer", 403)
        if shares <= 0:
            return apology("Cannot buy 0 shares", 403)

        # Calculate value of purchase
        name = quotes.get("name")
        value = quotes.get("price")
        total_purchase = value * shares

        #Calculate available cash
        db.execute("SELECT cash FROM users WHERE id =?",(user,))
        rows = db.fetchone()
        balance = rows[0]

        # Ensure user have money for transaction
        if total_purchase > balance:
            return apology("Cannot afford transaction", 403)

        #Add the transaction to the database
        else:
            cash_remaining = balance - total_purchase
            db.execute("UPDATE users SET cash =? WHERE id =?", (cash_remaining, user))
            db.execute("""INSERT INTO purchase
                        (id_user, symbol, name, shares, price, transacted)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """, (user, symbol, name, shares, value))
            conn.commit()

        # Display a message to the user on top
        flash("Bought!")
        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    user = session["user_id"]
    db.execute("SELECT symbol, shares, price, transacted FROM purchase WHERE id_user =?", (user,))
    rows = db.fetchall()

    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)

        # Query database for username
        db.execute("SELECT * FROM users WHERE username =?", (username,))
        rows = db.fetchone()

        # Ensure username exists and password is correct
        if rows == None and not check_password_hash(rows[2], password):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]
        session["username"] = rows[1]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    #Once the user fillout the information and click on button
    if request.method == "POST":
        s = request.form.get("symbol")
        symbol = s.upper()
        shares = lookup(symbol)

        #Ensure a symbol was submitted
        if not symbol or shares == None:
            return apology("must provide a Share name", 403)

        #Get the information from the API
        name = shares.get("name")
        price = shares.get("price")
        return render_template("quoted.html", name=name, price=price, symbol=symbol)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    #Once the user fillout the information and click on button
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)

        # Ensure Confirmation password was submitted
        elif not confirmation:
            return apology("must confirm password", 403)

        #Ensure both the password field and confirmation field are the same
        elif not password == confirmation:
            return apology("Password and Confirmation must be the same", 403)

        # Query database for username
        db.execute("SELECT * FROM users WHERE username =?",(username,))
        rows = db.fetchone()

        # Ensure username does not exists
        if not rows == None:
            return apology("Username already exists", 403)
        else:
            hash_pass = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", (username, hash_pass))
            conn.commit()

        # Remember which user has logged in
        db.execute("SELECT id FROM users WHERE username =?", (username,))
        rows = db.fetchone()
        session["user_id"] = rows[0]

        #Display a message to the user on top
        flash("Registered!")
        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user = session["user_id"]
    if request.method == "POST":
        symbol = request.form.get("symbol")

        quote = lookup(symbol)
        name = quote.get("name")

        # Check if the symbol exists
        if quote == None:
            return apology("Provide a valid symbol", 403)

        # Ensure is a positive intenger
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Must provide a positive integer", 403)
        if shares <= 0:
            return apology("Cannot buy 0 shares", 403)

        # Check number of shares
        db.execute("SELECT symbol, name, SUM(shares) as total_shares FROM purchase WHERE id_user =? GROUP BY symbol HAVING total_shares > 0",(user,))
        rows = db.fetchone()
        db.execute("SELECT cash FROM users WHERE id =?", (user,))
        cash = db.fetchone()

        if shares > rows[2]:
            return apology("Don't have enough shares", 403)
        else:
            # Calculate value of sell
            price = quote.get("price")
            total_sell = shares * price

            # Add transaction to the database
            cash_remaining = cash[0] + total_sell
            db.execute("UPDATE users SET cash =? WHERE id =?", (cash_remaining, user))
            db.execute("""INSERT INTO purchase
                            (id_user, symbol, name, shares, price, transacted)
                            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                            """, (user, symbol, name, (-shares), price))
            conn.commit()

            # Display a message to the user on top
            flash("Sold!")
            # Redirect user to home page
            return redirect("/")
    else:
        db.execute("SELECT symbol, name, SUM(shares) as total_shares FROM purchase WHERE id_user =? GROUP BY symbol HAVING total_shares > 0", (user,))
        rows = db.fetchall()
        return render_template("sell.html", rows=rows)

@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change user's Password"""

    user = session["user_id"]
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # Ensure old password was submitted
        if not old_password:
            return apology("must provide old password", 403)
        # Ensure old password was submitted
        if not new_password:
            return apology("must provide new password", 403)
        # Ensure old password was submitted
        if not confirmation:
            return apology("must confirm new password", 403)
        #Ensure both the password field and confirmation field are the same
        if not new_password == confirmation:
            return apology("Password and Confirmation must be the same", 403)

        # Query database for username
        db.execute("SELECT hash FROM users WHERE id =?", (user,))
        rows = db.fetchone()

        if check_password_hash(rows[0], old_password):
            print("ok")
        else:
            print("not ok")
        # Ensure username exists and password is correct
        if rows == None and not check_password_hash(rows[0], old_password):
            return apology("invalid password", 403)

        #Update database
        hash_new_pass = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=8)
        db.execute("UPDATE users SET hash =? WHERE id =?", (hash_new_pass, user))
        conn.commit()

        #Display a message to the user on top
        flash("Password Changed!")
        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("password.html")

@app.route("/funds", methods=["GET", "POST"])
@login_required
def funds():

    user=session["user_id"]
    if request.method == "POST":

        #Ensure the amount is a valid numer
        try:
            amount = float(request.form.get("amount"))
        except:
            return apology("Amount must be a positive number", 403)
        if amount < 0:
            return apology("Amount must be a positive number", 403)

        #Update database
        db.execute("UPDATE users SET cash = cash + ? WHERE id =?", (amount, user))
        conn.commit()

        #Display a message to the user on top
        flash("Money Added!")
        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("funds.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__ == "__main__":
    app.run()