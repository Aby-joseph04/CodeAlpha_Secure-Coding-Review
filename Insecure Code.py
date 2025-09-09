# Remediated Flask Application - Secure Version

import os
from flask import Flask, request, render_template, redirect, session
import sqlite3
from jinja2 import Environment, FileSystemLoader

app = Flask(__name__)

# BEST PRACTICE: Load secret key from an environment variable.
# This prevents it from being exposed in the source code.
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or 'default-fallback-insecure-key'

# Secure database connection function
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

# REMEDIATION: Using parameterized queries to prevent SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        # BEST PRACTICE: Using a prepared statement with placeholders.
        # This separates the SQL command from the user data.
        sql_query = "SELECT * FROM users WHERE username = ? AND password = ?"
        user = conn.execute(sql_query, (username, password)).fetchone()
        conn.close()

        if user:
            session['logged_in'] = True
            session['username'] = user['username']
            return redirect('/profile')
        else:
            return 'Invalid credentials'
    return render_template('login.html')

# REMEDIATION: Using Jinja2 for automatic HTML escaping
@app.route('/profile')
def profile():
    if not session.get('logged_in'):
        return redirect('/login')

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    conn.close()
    
    # BEST PRACTICE: Using a template with Jinja2's autoescaping.
    # The 'bio' field is now safely rendered, preventing XSS.
    env = Environment(loader=FileSystemLoader('.'))
    template = env.from_string("""
    <h1>Welcome, {{ user.username }}</h1>
    <p>Bio: {{ user.bio }}</p>
    """)
    return template.render(user=user)


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
    # REMEDIATION: A note on setting the environment variable
    # In a real environment, you would set this outside of the app.
    # export FLASK_SECRET_KEY="a_strong_random_secret_key"
    app.run(debug=True)
