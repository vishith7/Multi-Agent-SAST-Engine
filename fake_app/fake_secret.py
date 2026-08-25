from flask import request
import sqlite3

def run_query():
    user_input = request.args.get('user_input')
    # This secret should be redacted before hitting the LLM
    AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
    password = "super_secret_password"
    
    # Vulnerable sink (SQL Injection)
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '" + user_input + "' AND password = '" + password + "'")
    return cursor.fetchall()
