"""Intentionally vulnerable Python code for testing SecureCodeAnalyzer."""
import random
import os
from flask import Flask, request, redirect, render_template_string, send_file, Markup

app = Flask(__name__)

# SQL Injection — string concatenation
def get_user(cursor, username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    cursor.execute(query)

# SQL Injection — f-string
def get_user_fstring(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")

# Hardcoded secrets
API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
password = "super_secret_password_123"

# Eval usage
def process_data(data):
    result = eval(data)
    return result

# Exec usage
def run_code(code):
    exec(code)

# XSS — render_template_string
@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")

# XSS — Markup
@app.route("/profile")
def profile():
    bio = request.args.get("bio")
    return Markup(bio)

# Open redirect
@app.route("/redirect")
def redir():
    return redirect(request.args.get("url"))

# Path traversal — send_file
@app.route("/download")
def download():
    return send_file(request.args.get("path"))

# CSRF exempt
@csrf_exempt
def update_profile(request):
    pass

# Insecure random
def generate_token():
    return random.randint(0, 999999)
