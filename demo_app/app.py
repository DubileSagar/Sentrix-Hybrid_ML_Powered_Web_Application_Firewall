import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)
WAF_API_URL = "http://127.0.0.1:8000/analyze"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Demo App</title>
    <style>
        body { font-family: sans-serif; margin: 40px; background-color: #f9f9f9; }
        .box { border: 1px solid #ddd; background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
        .btn { padding: 10px 15px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 14px; }
        .btn:hover { background: #0056b3; }
        input { padding: 10px; width: 350px; margin-right: 10px; border: 1px solid #ccc; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>Sentrix Demo Application</h1>
    <p>This is a simulated vulnerable web application protected by the Sentrix WAF.</p>

    <div class="box">
        <h3>1. Simulated Login (Test SQL Injection)</h3>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username (try: admin' OR 1=1 --)" required>
            <input type="password" name="password" placeholder="Password" required>
            <button class="btn" type="submit">Login</button>
        </form>
    </div>

    <div class="box">
        <h3>2. Search (Test Cross-Site Scripting)</h3>
        <form action="/search" method="GET">
            <input type="text" name="q" placeholder="Search query (try: <script>alert(1)</script>)" required>
            <button class="btn" type="submit">Search</button>
        </form>
    </div>
    
    <div class="box">
        <h3>3. File Retrieval (Test Path Traversal)</h3>
        <form action="/files" method="GET">
            <input type="text" name="file" placeholder="File name (try: ../../etc/passwd)" required>
            <button class="btn" type="submit">Get File</button>
        </form>
    </div>
</body>
</html>
"""

BLOCK_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>403 Forbidden</title>
    <style>
        body { font-family: sans-serif; text-align: center; margin-top: 80px; background-color: #ffeaea; } 
        h1 { color: #d9534f; font-size: 48px; }
        .container { background: white; padding: 40px; border-radius: 10px; display: inline-block; box-shadow: 0 4px 15px rgba(217, 83, 79, 0.2); }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ 403 Forbidden</h1>
        <h2>Request Blocked by Sentrix WAF</h2>
        <p><i>Reason: {{ reason }}</i></p>
        <br><br>
        <a href="/" style="color: #007bff; text-decoration: none; font-weight: bold;">&larr; Return Home</a>
    </div>
</body>
</html>
"""

@app.before_request
def waf_middleware():
    """Intercept all requests and check with Sentrix WAF."""
    payload = {
        "method": request.method,
        "path": request.full_path,
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True),
        "client_ip": request.remote_addr or "127.0.0.1"
    }

    try:
        response = requests.post(WAF_API_URL, json=payload, timeout=2.0)
        if response.status_code == 200:
            decision = response.json()
            if decision.get("action") == "block":
                return render_template_string(BLOCK_HTML, reason=decision.get("reason", "Malicious activity detected")), 403
    except requests.exceptions.RequestException as e:
        print(f"Warning: WAF is unreachable ({e}). Failing open.")

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    return f"<h3>Login logic executed (WAF bypassed). Welcome {username}!</h3><a href='/'>Back</a>"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h3>Search logic executed (WAF bypassed). Results for: {q}</h3><a href='/'>Back</a>"

@app.route("/files")
def files():
    f = request.args.get("file", "")
    return f"<h3>File retrieval executed (WAF bypassed). Contents of: {f}</h3><a href='/'>Back</a>"

if __name__ == "__main__":
    app.run(port=5000, debug=True)
