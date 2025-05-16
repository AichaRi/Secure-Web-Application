# 🛡️ Flask Secure Demo App

This is a security-focused Flask web application that demonstrates:
- Secure user login and registration diasllowing SQL injection
- Role-Based Access Control (RBAC) 
- Secure comment posting with XSS protection
- Insecure comment route without XSS protection
- Raw SQL and hashed password demos

## 🚀 Features

- 🔐 User Authentication using `Flask-Login`
- 🧂 Password hashing using `bcrypt` or insecure `MD5`
- ✍️ Safe and Unsafe Comment Forms 
- 👮 Role-Based Access Control (`admin` vs `user`)
- 🔄 Admin RBAC Toggle (`ENABLE_RBAC`)

---


## ⚙️ Configuration

Inside `app.py`:

```python
ENABLE_RBAC = True       # Set to False to allow all users into /admin page


