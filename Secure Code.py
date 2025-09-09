# Vulnerable Flask Application - FOR EDUCATIONAL PURPOSES ONLY

from flask import Flask, request, render_template, redirect, session
import sqlite3

app = Flask(__name__)
# VULNERABILITY: Hardcoded secret key
# This is a major security risk as it can be easily exposed.
app.secret_key = 'this-is-a-very-insecure-hardcoded-secret-key'

# Insecure database connection function
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# A simple user table
# In a real app, passwords would be hashed and salted.
def create_table():
    conn = get_db_connection()
    conn.execute('CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, bio TEXT)')
    conn.commit()
    conn.close()

create_table()

# VULNERABILITY: SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        # VULNERABILITY: Directly concatenating user input into the SQL query
        # An attacker can use ' OR 1=1 -- to bypass authentication.
        sql_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(sql_query).fetchone()
        conn.close()

        if user:
            session['logged_in'] = True
            session['username'] = user['username']
            return redirect('/profile')
        else:
            return 'Invalid credentials'
    return render_template('login.html')

# VULNERABILITY: Cross-Site Scripting (XSS)
@app.route('/profile')
def profile():
    if not session.get('logged_in'):
        return redirect('/login')

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    conn.close()

    # VULNERABILITY: The bio field is rendered without sanitization.
    # An attacker can store a script in their bio that will execute on this page.
    profile_html = f"""
    <h1>Welcome, {user['username']}</h1>
    <p>Bio: {user['bio']}</p>
    """
    return profile_html # DANGEROUS: This returns raw HTML, which is a major XSS risk.

# A simple HTML template for login
@app.route('/login.html')
def login_page():
    return """
    <form method="post" action="/login">
        Username: <input name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    """

if __name__ == '__main__':
    app.run(debug=True)
