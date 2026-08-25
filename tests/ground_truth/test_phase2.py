import request
import sqlite3
import requests
import pickle

def test_raw_sqli():
    user_id = request.args.get("id")
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # (a) raw SQL injection
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

def test_param_sqli():
    user_id = request.args.get("id")
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # (b) parameterized query - SHOULD NOT BE FLAGGED
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

def test_ssrf_to_deserialization():
    url = request.args.get("url")
    # ssrf sink, deserialization source
    response = requests.get(url)
    
    # deserialization sink
    data = pickle.loads(response.content)
    return data
