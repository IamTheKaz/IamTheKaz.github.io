""" Kassandra Ring 3047272***** 3/3/2023 ***** SDEV 300 """

# program works with flask modules to render password protected html pages for a website
from datetime import datetime, timedelta  # For date
import csv
import string  # Used to make sure password meets specifications
import logging
from flask import Flask, flash, redirect, request, url_for, session, \
    render_template  # Does all the things needed for the website
from flask.logging import create_logger
from passlib.hash import sha256_crypt  # Encrypts user's password

# Global variables
PASSWORD_FILE = "pass_file.txt"  # File where username and pass-hash stored
COMMON_PASS = 'CommonPassword.txt'  # File containing common passwords
app = Flask(__name__)
app.secret_key = 'random string'
date = datetime.now()
application_log = create_logger(app)  # Variable needed for recording warnings


# Function disables current logging and uses custom override that is just for warning level
def record_logs():
    '''Function writes warnings to log_file.txt'''
    username = session['username']  # Gets username for warning log
    user_ip = request.remote_addr  # Gets user's IP address
    log = logging.getLogger('werkzeug')  # Gets regular system logging
    log.disabled = True  # Disables system logging so that only the warning logger is recording to file
    # Set up formatting for warning message to be printed in log_file.txt, appended so that all warnings are saved,
    # insures that date, time, and message is printed
    logging.basicConfig(filename='log_file.txt', filemode='a', level=logging.WARNING,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Message for warnings with username and user_ip added
    application_log.warning(username + " failed password validation. IP Address: " + user_ip)


# FUnction makes sure that the new password meets the same specifications as when registering,
# ensures that it is not the same as the current password, and does not match any listed in CommonPasswords.txt
def reset_validator(user_password):
    '''Function to check user's new password passes validation
    and does not match a list of common passwords'''
    try:  # Opens CommonPasswords.txt
        with open(COMMON_PASS, "r") as file:
            passwords = file.read()
            error = "Password successfully changed"

            # Condition for if new password matches any of the ones in CommonPasswords.txt
            if user_password in passwords:
                error = 'Password matches common passwords, please chose another'
                flash(error)
            # Condition for if new password is the same as current password
            elif sha256_crypt.verify(user_password, checknotreg(session['username'])):
                error = 'Your new password may not be the same as your old password'
                flash(error)
            # Condition for if new password does not meet specifications
            elif password_validator(user_password) is not None:
                error = password_validator(user_password)
                flash(error)
            return error

    # What the program does if the file CommonPasswords.txt cannot be read
    except FileNotFoundError as file_e:
        print("Could not find file called " + COMMON_PASS)
        # all info about the error printed to the server for support to see/debug
        print(file_e.args)
        error = "Account database isn't available right now, " \
                "please try back later or contact support"
        flash(error)
        return redirect(url_for('login'))
    except Exception as other_e:
        print("Could not read file " + COMMON_PASS)
        # all info about the error printed to the server for support to see/debug
        print(other_e.args)
        error = "Account database isn't available right now, " \
                "please try back later or contact support"
        flash(error)
        return redirect(url_for('login'))


# Once the password has been approved by above function this function changes the hash in pass_file.txt
def change_pass(password):
    '''Function to change password'''

    # Creates a new hash for the new password
    new_hash = sha256_crypt.hash(password)  # encrypt password before storing to file
    try:  # Reads pass_file.txt and puts the users current hashed password into a variable called old_password.
        # Then it replaces the old hash with the new hash created above
        with open(PASSWORD_FILE, 'r') as users:
            # Reads file and puts it into variable called data
            data = users.read()
            # Finds the user and puts its hased password into a variable called old_password
            old_password = checknotreg(session['username'])
            # Looks in the variable data and searches for the value of old_password
            # and replaces it with the value of new_hash
            data = data.replace(old_password, new_hash)
        # Once the variable data has been successfully changed,
        # replace the contents of pass_file.txt with the value of variable data
        with open(PASSWORD_FILE, 'w') as file:
            file.write(data)
            return 'Rewrite Complete'

    # What the pprogram does if pass_file.txt cannot be read or changed
    except FileNotFoundError as file_e:
        print("Could not find file called " + PASSWORD_FILE)
        # all info about the error printed to the server for support to see/debug
        print(file_e.args)
        error = "Account database isn't available right now, " \
                "please try back later or contact support"
        flash(error)
        return redirect(url_for('home'))
    except Exception as other_e:
        print("Could not write to file " + PASSWORD_FILE)
        # all info about the error printed to the server for support to see/debug
        print(other_e.args)
        error = "Account database isn't available right now, " \
                "please try back later or contact support"
        flash(error)
        return redirect(url_for('home'))


def password_validator(password):
    '''Function ensures user password meets specifications'''
    special_char = string.punctuation

    # Conditions for password
    if len(password) < 12:
        error = "Password too short!"
        flash(error)
    elif not any(x in special_char for x in password):
        error = "Password must have at least one special character"
        flash(error)
    elif not any(x.isupper() for x in password):
        error = "Password must have at least one uppercase letter"
        flash(error)
    elif not any(x.islower() for x in password):
        error = "Password must have at least one lowercase letter"
        flash(error)
    elif not any(x.isdigit() for x in password):
        error = "Password must have at least one number"
        flash(error)
    else:
        error = None
    # Send message to webpage
    flash(error)

    # Enables error to be passed to another function
    return error


def checknotreg(user_input):
    '''Funtion looks for pass_file.txt and reads it.
    Then it flashes an error if one is found or if the user already exists.
    Errors are strings not to show user the error,
    but to make it easier to write the code that looks for these errors'''
    try:
        # Opens file
        with open(PASSWORD_FILE, "r") as users:
            # Reads file
            for record in users:
                if len(record) == 0:
                    print("File is empty")
                    return None
                username, password = record.split(',')
                password = password.rstrip('\n')
                if username == user_input:
                    return password

    # What to do in case of exceptions
    except FileNotFoundError as file_e:
        print('File not found:' + PASSWORD_FILE)
        print(file_e.args)
        error = "Account database isn't available right now, " \
                "please try back later or contact support"
        flash(error)
        return redirect(url_for('login'))
    except Exception as other_e:
        print('No permissions to open this file or data in it not '
              'in correct format: ', PASSWORD_FILE)
        print(other_e.args)
        error = "Account database isn't available right now, " \
                "please try back later or contact support"
        flash(error)
        return redirect(url_for('login'))
    return None


def write_user_to_file(username, password):
    ''' Write given username and password to the password file '''
    pass_hash = sha256_crypt.hash(password)  # encrypt password before storing to file
    try:  # Add account info to account database
        with open(PASSWORD_FILE, 'a', newline='') as pass_file:
            writer = csv.writer(pass_file)
            writer.writerow([username, pass_hash])
            return
    except FileNotFoundError as file_e:
        print("Could not find file called " + PASSWORD_FILE)
        # all info about the error printed to the server for support to see/debug
        print(file_e.args)
        error = "Account database isn't available right now, " \
                "please try back later or contact support"
        flash(error)
        return redirect(url_for('register'))
    except Exception as other_e:
        print("Could not append to file " + PASSWORD_FILE)
        # all info about the error printed to the server for support to see/debug
        print(other_e.args)
        error = "Account database isn't available right now, " \
                "please try back later or contact support"
        flash(error)
        return redirect(url_for('register'))


# Sets a timer for 30 seconds for the session
@app.before_request
def session_timeout():
    '''Function runs before requests to set session timer'''
    session.permanent = True
    app.permanent_session_lifetime = timedelta(seconds=30)


# Set home.html as the main page or root if the user is already logged in.
# If they are not, redirect to login page and start a session
@app.route('/')
def home():
    '''Function brings user to home after it starts a session'''
    # Condition for if user is already logged in
    if 'username' in session:
        username = session['username']
        return render_template('home.html', date=date, username=username)
    # What to do if user is not logged in
    session.pop('username', None)
    return redirect(url_for('login'))


# Processes the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Function processes the login page. Flashes errors if bad input is entered.
    Sends to home page if everything looks good.
    If there is no one registered under the name, render register.html.'''

    # Variable for error messages
    error = None

    # Looks for POST information and processes it
    if request.method == "POST":
        session['username'] = request.form['username']
        password = request.form['password']
        username = session['username']

        # Conditions for bad input
        if not username:
            error = 'Please enter your Username.'
            flash(error)
            return redirect(url_for('login'))
        if not password:
            error = 'Please enter your Password.'
            flash(error)
            return redirect(url_for('login'))
        if checknotreg(username) is None:
            error = 'Please register first'
            flash(error)
            return redirect(url_for('register'))
        if sha256_crypt.verify(password, checknotreg(username)) is False:
            error = 'Invalid password'
            flash(error)
            record_logs()
            return redirect(url_for('login'))

        # Once there are no errors, render home page sending username and date to home.html
        return render_template('home.html', date=date, username=username)

    # If there are still errors reload the login page and flash errors
    return render_template('login.html', error=error)


# Process the register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    '''Function renders register page'''

    # Variable for error messages
    error = None

    # If a GET request is made reload register.html
    if request.method == "GET":
        return render_template('register.html', style='home', pagename='Registration')

    # IF POST request is made take the information and check it
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Conditions for input
        if checknotreg(username) is None:
            # Conditions for field username or password being empty
            # Both errors will reload register.html and print its error on the webpage
            if not username:
                error = "Please make a username"
                flash(error)
                return redirect(url_for('register'))
            if not password:
                error = "Enter a password containing at least 1 uppercase character, " \
                        "1 lowercase character, 1 number and 1 special character"
                flash(error)
                return redirect(url_for('register'))
            # Condition for name too short
            if len(username) < 4:
                error = "Choose a username with more than 4 characters please"
                flash(error)
                return redirect(url_for('register'))
            # Conditions for bad password input
            # Error will post based on what password_validator returns
            if password_validator(password) is not None:
                error = password_validator(password)
                flash(error)
                return redirect(url_for('register'))
            # Condition for good input
            # Writes to file to goes back to the login page
            error = "Successful registration, please log in to continue"
            flash(error)
            write_user_to_file(username, password)
            return redirect(url_for('login'))
        # Condition for name already chosen
        error = "Username taken, please pick another username"
        flash(error)
        return render_template('register.html')

    # If there is still an error, post that error and reload the register page
    return render_template('register.html')


# Function takes password value from web page user_reset and sends it to functions to check its validity.
# If new password is valid it will return to the login page for the user to use the new password
@app.route('/user_reset', methods=['GET', 'POST'])
def user_reset():
    '''Function processes user reset password request'''
    if 'username' in session:
        if request.method == "GET":
            return render_template('user_reset.html')

        # IF POST request is made take the information and check it
        if request.method == "POST":
            password = request.form["password"]
            # Condition for if new password is not valid
            if reset_validator(password) is not 'Password successfully changed':
                error = reset_validator(password)
                flash(error)
                return redirect(url_for('user_reset'))
            # Calls function to change the password
            change_pass(password)
            # Upon successful password change, redirect user to login page
            return redirect(url_for('login'))
        # In case of errors keep user on user_reset page
        return render_template('user_reset.html')
    # If session has expired or user has not logged in, redirect user back to login page
    return redirect(url_for('login'))


# Set age.html to come off of the root
@app.route('/age.html')
def age():
    '''Renders age.html'''
    if 'username' in session:
        return render_template('age.html')
    return render_template('login.html')


# Set state.html to come off of the root
@app.route('/state.html')
def state():
    '''Renders state.html'''
    if 'username' in session:
        return render_template('state.html')
    return render_template('login.html')


# Set vote.html to come off of the root
@app.route('/vote.html')
def vote():
    '''Renders vote.html'''
    if 'username' in session:
        return render_template('vote.html')
    return render_template('login.html')
