import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)
WAF_API_URL = "http://127.0.0.1:8000/analyze"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentrix WAF Protected Environment</title>
    <style>
        :root {
            --bg-color: #0b0f19;
            --panel-bg: rgba(20, 25, 40, 0.6);
            --accent-blue: #00e5ff;
            --accent-red: #ff3366;
            --text-main: #e2e8f0;
            --text-muted: #94a3b8;
        }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; padding: 40px 20px; 
            background: radial-gradient(circle at top right, #1a233a 0%, var(--bg-color) 100%);
            color: var(--text-main);
            min-height: 100vh;
        }
        .header { text-align: center; margin-bottom: 50px; }
        .header h1 { font-size: 2.5rem; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 10px; text-shadow: 0 0 10px rgba(0,229,255,0.5); }
        .header p { color: var(--text-muted); font-size: 1.1rem; }
        
        .container { max-width: 900px; margin: 0 auto; display: grid; gap: 30px; }
        
        .box {
            background: var(--panel-bg);
            border: 1px solid rgba(255,255,255,0.05);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            transition: transform 0.3s ease, border-color 0.3s ease;
        }
        .box:hover { transform: translateY(-5px); border-color: rgba(0,229,255,0.3); }
        
        .box h3 { border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 10px; margin-top: 0; color: var(--accent-blue); display: flex; justify-content: space-between; align-items: center;}
        
        .form-row { display: flex; gap: 15px; margin-top: 20px; flex-wrap: wrap; }
        input { 
            flex: 1; padding: 12px 15px; min-width: 250px;
            background: rgba(0,0,0,0.3); color: white;
            border: 1px solid rgba(255,255,255,0.1); border-radius: 6px;
            font-size: 1rem; transition: all 0.3s ease;
        }
        input:focus { outline: none; border-color: var(--accent-blue); box-shadow: 0 0 10px rgba(0,229,255,0.2); }
        input::placeholder { color: rgba(255,255,255,0.3); }
        
        .btn { 
            padding: 12px 25px; background: transparent; 
            color: var(--accent-blue);
            border: 1px solid var(--accent-blue); 
            border-radius: 6px; cursor: pointer; font-size: 1rem; font-weight: bold;
            transition: all 0.3s ease; text-transform: uppercase; letter-spacing: 1px;
        }
        .btn:hover { background: var(--accent-blue); color: #000; box-shadow: 0 0 15px rgba(0,229,255,0.4); }
        
        .hint {
            margin-top: 15px;
            font-size: 0.9rem; color: var(--text-muted);
            background: rgba(255,255,255,0.03); padding: 10px; border-radius: 6px;
            border-left: 3px solid var(--accent-red);
        }
        .hint p { margin: 0 0 5px 0; }
        .hint code { color: #ffeb3b; background: rgba(0,0,0,0.5); padding: 2px 5px; border-radius: 3px; font-family: monospace; }
        .badge { background: rgba(255,51,102,0.15); color: var(--accent-red); padding: 5px 10px; border-radius: 20px; font-size: 0.75rem; text-transform: uppercase; font-weight: bold; border: 1px solid rgba(255,51,102,0.3); }

        .guide-box {
            background: linear-gradient(135deg, rgba(0, 229, 255, 0.1) 0%, rgba(20, 25, 40, 0.6) 100%);
            border: 1px solid rgba(0, 229, 255, 0.2);
            padding: 20px; border-radius: 12px; margin-bottom: 30px;
        }
        .guide-box h2 { margin-top: 0; color: #fff; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Sentrix WAF Demo App</h1>
        <p>Simulated vulnerable endpoints protected by the ML-Powered Firewall</p>
    </div>

    <div class="container">
        <div class="guide-box">
            <h2>📘 How to use this Demo</h2>
            <p>This page contains purposefully vulnerable input fields. When you submit a request, it is intercepted and evaluated by the <b>Sentrix FastAPI service</b> <i>before</i> reaching the vulnerable endpoint.</p>
            <p>1. Try entering a normal benign string (like "hello" or "admin"). It should pass through.<br>
               2. Try entering a malicious payload from the hints below.<br>
               3. If the payload is malicious, Sentrix will block it and serve a 403 Forbidden intercept page.<br>
               4. Check the <b>Streamlit Dashboard (Port 8501)</b> to see the blocks represented in real-time charts.</p>
        </div>

        <div class="box">
            <h3>Login endpoint <span class="badge">SQL Injection (SQLi)</span></h3>
            <div class="hint">
                <p><b>Goal:</b> Bypass logic or extract DB structures.</p>
                <p><b>Try payload:</b> <code>admin' OR 1=1 --</code> or <code>' UNION SELECT null, version()--</code></p>
            </div>
            <form action="/login" method="POST" class="form-row">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button class="btn" type="submit">Login</button>
            </form>
        </div>

        <div class="box">
            <h3>Search endpoint <span class="badge">Cross-Site Scripting (XSS)</span></h3>
            <div class="hint">
                <p><b>Goal:</b> Inject malicious client-side JavaScript.</p>
                <p><b>Try payload:</b> <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code> or <code>"&gt;&lt;img src=x onerror=prompt(1)&gt;</code></p>
            </div>
            <form action="/search" method="GET" class="form-row">
                <input type="text" name="q" placeholder="Search query..." required>
                <button class="btn" type="submit">Search</button>
            </form>
        </div>
        
        <div class="box">
            <h3>File Retrieval endpoint <span class="badge">Path Traversal & CMD Inject</span></h3>
            <div class="hint">
                <p><b>Goal:</b> Access unauthorized system files or execute OS commands.</p>
                <p><b>Try payload (Traversal):</b> <code>../../../../etc/passwd</code></p>
                <p><b>Try payload (CMDi):</b> <code>hello.txt; cat /etc/shadow</code></p>
            </div>
            <form action="/files" method="GET" class="form-row">
                <input type="text" name="file" placeholder="File name e.g. report.pdf" required>
                <button class="btn" type="submit">Get File</button>
            </form>
        </div>
    </div>
</body>
</html>
"""

BLOCK_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Forbidden - Threat Intercepted</title>
    <style>
        body { 
            font-family: 'Courier New', Courier, monospace; 
            background-color: #0b0f19; color: #ff3366; 
            margin: 0; height: 100vh; display: flex; 
            align-items: center; justify-content: center;
            background-image: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255, 51, 102, 0.03) 2px, rgba(255, 51, 102, 0.03) 4px);
        }
        .container { 
            background: rgba(20, 25, 40, 0.8); padding: 50px; 
            border: 2px solid #ff3366; border-radius: 8px; 
            text-align: center; box-shadow: 0 0 40px rgba(255, 51, 102, 0.3), inset 0 0 20px rgba(255, 51, 102, 0.1); 
            max-width: 600px; width: 90%;
            animation: pulse-border 2s infinite;
        }
        @keyframes pulse-border {
            0% { box-shadow: 0 0 40px rgba(255, 51, 102, 0.3); }
            50% { box-shadow: 0 0 60px rgba(255, 51, 102, 0.6); }
            100% { box-shadow: 0 0 40px rgba(255, 51, 102, 0.3); }
        }
        h1 { font-size: 3rem; margin-top: 0; text-transform: uppercase; text-shadow: 0 0 10px #ff3366; }
        .reason-box { background: rgba(0,0,0,0.5); color: #fff; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px dashed #ff3366; font-size: 1.1rem;}
        a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: transparent; color: #ff3366; text-decoration: none; border: 1px solid #ff3366; font-weight: bold; transition: 0.3s; text-transform: uppercase;}
        a:hover { background: #ff3366; color: #000; box-shadow: 0 0 15px #ff3366; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠ THREAT INTERCEPTED</h1>
        <h2>403 Forbidden</h2>
        <p>Your request was flagged as malicious and terminated by Sentrix WAF.</p>
        <div class="reason-box">Matched Signature: <b>{{ reason }}</b></div>
        <a href="/">&lt; Return to Safety</a>
    </div>
</body>
</html>
"""

SUCCESS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>200 OK - Access Granted</title>
    <style>
        body { 
            font-family: 'Courier New', Courier, monospace; 
            background-color: #0b0f19; color: #00e5ff; 
            margin: 0; height: 100vh; display: flex; 
            align-items: center; justify-content: center;
            background-image: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0, 229, 255, 0.03) 2px, rgba(0, 229, 255, 0.03) 4px);
        }
        .container { 
            background: rgba(20, 25, 40, 0.8); padding: 50px; 
            border: 2px solid #00e5ff; border-radius: 8px; 
            text-align: center; box-shadow: 0 0 40px rgba(0, 229, 255, 0.3), inset 0 0 20px rgba(0, 229, 255, 0.1); 
            max-width: 600px; width: 90%;
        }
        h1 { font-size: 3rem; margin-top: 0; text-transform: uppercase; text-shadow: 0 0 10px #00e5ff; }
        .reason-box { background: rgba(0,0,0,0.5); color: #fff; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px dashed #00e5ff; font-size: 1.1rem; word-break: break-all;}
        a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: transparent; color: #00e5ff; text-decoration: none; border: 1px solid #00e5ff; font-weight: bold; transition: 0.3s; text-transform: uppercase;}
        a:hover { background: #00e5ff; color: #000; box-shadow: 0 0 15px #00e5ff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ACCESS GRANTED</h1>
        <h2>200 OK</h2>
        <p>Traffic successfully passed Sentrix WAF inspection.</p>
        <div class="reason-box">Payload executed:<br><br><b>{{ payload }}</b></div>
        <a href="/">&lt; Return to Dashboard</a>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    return render_template_string(SUCCESS_HTML, payload=f"Login logic executed for username: {username}")

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string(SUCCESS_HTML, payload=f"Search logic executed for query: {q}")

@app.route("/files")
def files():
    f = request.args.get("file", "")
    return render_template_string(SUCCESS_HTML, payload=f"File retrieval executed. Target: {f}")

if __name__ == "__main__":
    app.run(port=5001, debug=True)
