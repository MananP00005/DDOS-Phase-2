from flask import Flask, jsonify, render_template, abort, request, Response
import time, os, random, hashlib, threading

app = Flask(__name__)

active_requests = 0
total_requests  = 0
lock = threading.Lock()

PAGES = ['programs', 'about', 'admissions', 'research']

# Detect if running as sinkhole container
SINKHOLE_MODE = os.environ.get('SINKHOLE_MODE') == 'true'

# ── Sinkhole mode — all requests return fake 503 ──────────────────
if SINKHOLE_MODE:
    SINKHOLE_BODY = """<!DOCTYPE html>
<html>
<head><title>503 Service Unavailable</title></head>
<body>
<h1>Service Unavailable</h1>
<p>The server is temporarily unable to service your request
due to maintenance downtime or capacity problems.
Please try again later.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at {host} Port 80</address>
</body>
</html>"""

    def fake_request_id():
        return hashlib.md5(
            f"{time.time()}{random.random()}".encode()
        ).hexdigest()[:16]

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def sinkhole_catch_all(path):
        ip    = request.headers.get('X-Real-IP', request.remote_addr)
        delay = random.uniform(1.5, 5.0)
        time.sleep(delay)
        padding = " " * random.randint(0, 120)
        host    = request.headers.get('Host', '<SERVER_EXTERNAL_IP>')  # ← Change to your server's external IP
        body    = SINKHOLE_BODY.format(host=host) + f"<!-- {padding} -->"
        print(f"[SINKHOLE] {ip} → /{path} — fake 503 after {delay:.1f}s")
        return Response(
            body,
            status=503,
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Retry-After":  str(random.randint(20, 45)),
                "Server":       "Apache/2.4.41 (Ubuntu)",
                "X-Request-ID": fake_request_id(),
                "Connection":   "keep-alive",
            }
        )

# ── Normal mode — real site ───────────────────────────────────────
else:
    @app.route('/')
    @app.route('/index.html')
    def index():
        global total_requests
        with lock:
            total_requests += 1
        return render_template('index.html')

    @app.route('/pages/<page_name>.html')
    def pages(page_name):
        global total_requests
        with lock:
            total_requests += 1
        if page_name not in PAGES:
            abort(404)
        return render_template(f'pages/{page_name}.html')

    @app.route('/heavy')
    def heavy():
        global active_requests, total_requests
        with lock:
            active_requests += 1
            total_requests  += 1
        try:
            result = 0
            for i in range(500000):
                result += i * i
            time.sleep(0.5)
            return jsonify({
                "status":  "ok",
                "result":  result,
                "message": "Request processed"
            })
        finally:
            with lock:
                active_requests -= 1

    @app.route('/api/data')
    def api_data():
        global total_requests
        with lock:
            total_requests += 1
        time.sleep(0.1)
        return jsonify({
            "students": 42000,
            "programs": 180,
            "status":   "operational"
        })

    @app.route('/status')
    def status():
        return jsonify({
            "active_requests": active_requests,
            "total_requests":  total_requests,
            "workers":         3,
            "status":          "running"
        })

    @app.route('/ping')
    def ping():
        return jsonify({"status": "ok"})

    # Honeypot endpoints
    FAKE_ADMIN_HTML = """<!DOCTYPE html>
<html><head><title>Admin Login</title></head>
<body><h2>Admin Panel</h2>
<form method="POST">
<input type="text" name="user" placeholder="Username">
<input type="password" name="pwd" placeholder="Password">
<button type="submit">Log In</button>
</form></body></html>"""

    @app.route('/admin',      methods=['GET','POST'])
    @app.route('/wp-admin',   methods=['GET','POST'])
    @app.route('/phpmyadmin', methods=['GET','POST'])
    @app.route('/login',      methods=['GET','POST'])
    def honeypot():
        ip = request.headers.get('X-Real-IP', request.remote_addr)
        print(f"[HONEYPOT] {ip} hit {request.path}")
        return Response(FAKE_ADMIN_HTML, status=200,
                        headers={"Content-Type": "text/html",
                                 "Server": "Apache/2.4.41 (Ubuntu)"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)
