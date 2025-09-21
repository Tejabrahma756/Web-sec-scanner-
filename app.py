import os
import google.generativeai as genai
from flask import Flask, request, jsonify, render_template
import subprocess, requests, socket

app = Flask(__name__)

# Root renders the home.html (the UI above)
@app.route("/")
def home():
    return render_template("home.html")


# ----- NMAP -----
@app.route('/scan/nmap')
def scan_nmap():
    target = request.args.get('target')
    if not target:
        return jsonify({"error": "Please provide ?target=<host>"}), 400
    try:
        proc = subprocess.run(["nmap", "-F", target], capture_output=True, text=True, timeout=60)
        return jsonify({"scanner": "nmap", "target": target, "result": proc.stdout})
    except Exception as e:
        return jsonify({"scanner": "nmap", "error": str(e)}), 500

# ----- NIKTO -----
@app.route('/scan/nikto')
def scan_nikto():
    target = request.args.get('target')
    if not target:
        return jsonify({"error": "Please provide ?target=<url_or_host>"}), 400
    try:
        proc = subprocess.run(["nikto", "-h", target], capture_output=True, text=True, timeout=300)
        return jsonify({"scanner": "nikto", "target": target, "result": proc.stdout})
    except Exception as e:
        return jsonify({"scanner": "nikto", "error": str(e)}), 500

# ----- SECURITY HEADERS -----
@app.route('/scan/headers')
def scan_headers():
    target = request.args.get('target')
    if not target:
        return jsonify({"error": "Please provide ?target=<url_or_host>"}), 400
    url = target if target.startswith("http") else "http://" + target
    try:
        r = requests.get(url, timeout=10)
        return jsonify({"scanner": "headers", "target": url, "headers": dict(r.headers)})
    except Exception as e:
        return jsonify({"scanner": "headers", "error": str(e)}), 500

# ----- ROBOTS.TXT -----
@app.route('/scan/robots')
def scan_robots():
    target = request.args.get('target')
    if not target:
        return jsonify({"error": "Please provide ?target=<url_or_host>"}), 400
    url = target if target.startswith("http") else "http://" + target
    try:
        resp = requests.get(url.rstrip("/") + "/robots.txt", timeout=8)
        if resp.status_code == 200:
            return jsonify({"scanner": "robots", "target": url, "robots": resp.text})
        else:
            return jsonify({"scanner": "robots", "target": url, "robots": f"Not found (HTTP {resp.status_code})"})
    except Exception as e:
        return jsonify({"scanner": "robots", "error": str(e)}), 500

# ----- DIRECTORY LISTING -----
@app.route('/scan/dirlisting')
def scan_dirlisting():
    target = request.args.get('target')
    if not target:
        return jsonify({"error": "Please provide ?target=<url_or_host>"}), 400
    url = target if target.startswith("http") else "http://" + target
    try:
        resp = requests.get(url, timeout=10)
        detected = "Index of /" in resp.text or "Directory listing" in resp.text or "Parent Directory" in resp.text
        return jsonify({"scanner": "dirlisting", "target": url, "directory_listing": detected})
    except Exception as e:
        return jsonify({"scanner": "dirlisting", "error": str(e)}), 500

# ----- SUBDOMAIN ENUM (simple wordlist probe) -----
@app.route('/scan/subdomains')
def scan_subdomains():
    target = request.args.get('target')
    if not target:
        return jsonify({"error": "Please provide ?target=<domain>"}), 400
    domain = target.split("/")[0].replace("http://", "").replace("https://", "")
    wordlist = ["www", "mail", "ftp", "test", "dev", "api"]
    found = []
    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append({"subdomain": fqdn, "ip": ip})
        except Exception:
            continue
    return jsonify({"scanner": "subdomains", "target": domain, "found": found})

# ----- RUN ALL (POST) -----
@app.route('/scan/all', methods=['POST'])
def scan_all():
    data = request.get_json(silent=True) or {}
    target = data.get('target') or ""
    if not target:
        return jsonify({"error": "POST JSON {\"target\": \"example.com\"}"}), 400

    # call each endpoint functionally (simpler to reuse above logic)
    results = {}
    # nmap
    try:
        nmap_proc = subprocess.run(["nmap", "-F", target], capture_output=True, text=True, timeout=60)
        results['nmap'] = nmap_proc.stdout
    except Exception as e:
        results['nmap'] = f"ERROR: {e}"
    # nikto
    try:
        nikto_proc = subprocess.run(["nikto", "-h", target], capture_output=True, text=True, timeout=300)
        results['nikto'] = nikto_proc.stdout
    except Exception as e:
        results['nikto'] = f"ERROR: {e}"
    # headers
    try:
        url = target if target.startswith("http") else "http://" + target
        r = requests.get(url, timeout=10)
        results['headers'] = dict(r.headers)
    except Exception as e:
        results['headers'] = f"ERROR: {e}"
    # robots
    try:
        url = target if target.startswith("http") else "http://" + target
        resp = requests.get(url.rstrip("/") + "/robots.txt", timeout=8)
        results['robots'] = resp.text if resp.status_code == 200 else f"Not found (HTTP {resp.status_code})"
    except Exception as e:
        results['robots'] = f"ERROR: {e}"
    # dirlisting
    try:
        url = target if target.startswith("http") else "http://" + target
        resp = requests.get(url, timeout=8)
        detected = "Index of /" in resp.text or "Directory listing" in resp.text or "Parent Directory" in resp.text
        results['dirlisting'] = detected
    except Exception as e:
        results['dirlisting'] = f"ERROR: {e}"
    # subdomains
    try:
        domain = target.split("/")[0].replace("http://", "").replace("https://", "")
        wl = ["www","mail","ftp","test","dev","api"]
        found = []
        for sub in wl:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append({"subdomain": fqdn, "ip": ip})
            except:
                pass
        results['subdomains'] = found
    except Exception as e:
        results['subdomains'] = f"ERROR: {e}"

    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

# configure with your API key (set it as env var for safety)
genai.configure(api_key=os.getenv("AIzaSyBwL83dxR8t6ZecR7B83Bvn8fYJiQW0ehU"))

# load a model
model = genai.GenerativeModel("gemini-1.5-flash")

# generate content
response = model.generate_content("Explain the scan results in simple terms")

print(response.text)

