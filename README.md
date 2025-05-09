## Overview

This is a simple web app built using Flask. It allows users to register, log in, and post comments.  
The goal of this project is to demonstrate how common web security issues like SQL Injection and XSS (Cross-Site Scripting) work, and how to prevent them.

You can turn security features on or off using the settings in the code.

---

##  How to Run the Application

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the required dependencies

##### Windows:
```zsh
pip install -r requirements.txt 
```

##### macOS/Linux:
```zsh
pip3 install -r requirements.txt
```

## Usage

##### Windows:
```zsh
python app.py
```
##### macOS/Linux:
```zsh
python3 app.py

Run the app

python app.py

How to Test Security Features
1. Test SQL Injection

    In app.py, change this line:

ENABLE_SQLI_DEMO = True

Now the app uses insecure raw SQL (not safe).

Go to the login page and try this as the username:

    ' OR '1'='1

    This shows how SQL injection can manipulate queries in the database .

2. Test XSS (Cross-Site Scripting)

    uncomment the part for sanitizeing the input
    after logging in:
   
    Post this as a comment:

    <script>alert('XSS demo!');</script>

    A pop-up will appear.
    This shows that XSS is working when comments are not sanitized.

    Try the same on the normal comments page (/dashboard) after the toggle is off.
    There, scripts are blocked, this shows how sanitizing protects against XSS.

3. Role Access

    In app.py, change this line:

    ENABLE_ROLE_TOGGLE = True

    Now the registration page will show a dropdown to choose between "user" or "admin".

    When set to False, new users are automatically created as admins.


```
