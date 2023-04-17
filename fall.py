from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import random
import sqlite3
app = Flask(__name__)
app.secret_key = 'secret_key'  # Set the secret key for session management

conn = sqlite3.connect('users.db')
#c = conn.cursor()

# Create a table to store authorized users
conn.execute('''CREATE TABLE IF NOT EXISTS authorized_users
             (username text, password text)''')

conn.execute("INSERT INTO authorized_users (username, password) VALUES (?, ?)", ('aarnav', 'ismpro'))
conn.execute("INSERT INTO authorized_users (username, password) VALUES (?, ?)", ('ismpro', 'winter'))
conn.commit()

# Query the table to get all users
result = conn.execute("SELECT username, password FROM authorized_users")
authorized_users = dict(result.fetchall())

# Close the database connection
conn.close()

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def lcm(a, b):
    return a * b // gcd(a, b)

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def generate_keys(p, q):
    n = p * q
    phi = lcm(p-1, q-1)
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    key, n = pk
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    key, n = pk
    try:
        plain = [chr(pow(char, key, n)) for char in ciphertext]
    except ValueError:
        return None
    return ''.join(plain)

@app.route('/')
@app.route('/')
def home():
    # If the user is not logged in, redirect them to the login page
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # If the user is logged in but not authorized, redirect them to the login page with an error message
    if session['username'] not in authorized_users:
        session.clear()
        error = 'Unauthorized access. Please log in with an authorized account.'
        return redirect(url_for('login', error=error))
    
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # If the user is already logged in, redirect them to the encryption page
    if 'username' in session:
        return redirect(url_for('home'))
    
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in authorized_users and authorized_users[username] == password:
            # If the username and password are correct, set the user as logged in
            session['username'] = username
            return redirect(url_for('home'))
        else:
            error = 'Invalid username or password. Please try again.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    # Clear the session and redirect the user to the login page
    session.clear()
    return redirect(url_for('login'))

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    # If the user is not logged in, redirect them to the login page
    if 'username' not in session:
        return redirect(url_for('login'))
    
    message = request.form['message']
    p = int(request.form['p'])
    q = int(request.form['q'])
    public, private = generate_keys(p, q)
    encrypted = encrypt(public, message)
    return render_template('result.html', encrypted_message=encrypted, private_key=private, public_key=public)
if __name__ == '__main__':
    app.run(debug=True)





