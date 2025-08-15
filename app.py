import time
import threading
import uuid
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for
from zapv2 import ZAPv2

app = Flask(__name__)

# --- ZAP Config ---
ZAP_API_KEY = '12345'
ZAP_PROXY = 'http://127.0.0.1:8080'
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})

# Dictionary to hold the status of active scans by scan ID
scan_status = {}
# Dictionary to store final scan results for history.
scan_results_history = {}

# Dictionary with mitigation advice for common OWASP vulnerabilities.
# The keys are a simplified version of the alert names.
MITIGATION_ADVICE = {
    "SQL Injection": "Use parameterized queries or prepared statements to prevent attackers from manipulating database queries.",
    "Cross-Site Scripting (XSS)": "Encode user input before displaying it on a web page to prevent malicious scripts from being executed.",
    "Cross-Site Request Forgery (CSRF)": "Use anti-CSRF tokens to ensure that all requests are legitimate and initiated by the user.",
    "Path Traversal": "Validate and sanitize user input that interacts with the file system. Use an allow-list of safe paths and avoid using user input directly in file paths.",
    "OS Command Injection": "Avoid using shell commands with user-provided input. If necessary, use a safe API and validate the input with an allow-list of permitted characters."
}


# ---------------- Threading Function for Targeted Scan ----------------

def run_targeted_scan(target_url, scan_id):
    """
    Function to run a targeted OWASP Top 10 scan in a single, non-blocking thread.
    """
    try:
        # --- SPIDER SCAN ---
        scan_status[scan_id] = {'status': '0', 'phase': 'spidering'}
        print(f"Starting spider scan for {scan_id} on {target_url}")
        
        zap.spider.set_option_thread_count(20)
        zap.spider.set_option_max_depth(3)
        zap.spider.set_option_max_children(50)
        
        spider_scan_id = zap.spider.scan(target_url)
        while int(zap.spider.status(spider_scan_id)) < 100:
            spider_status = zap.spider.status(spider_scan_id)
            scan_status[scan_id] = {'status': spider_status, 'phase': 'spidering'}
            time.sleep(1)
        
        pages = zap.spider.results(spider_scan_id)
        
        print(f"Spider scan completed for {scan_id}. Found {len(pages)} pages.")

        # --- TARGETED ACTIVE SCAN (OWASP Top 10) ---
        scan_status[scan_id] = {'status': '0', 'phase': 'active_scanning'}
        print(f"Starting targeted active scan for {scan_id} on {target_url}")

        zap.ascan.disable_all_scanners()
        
        # A selection of scanner IDs related to OWASP Top 10
        # 40018: SQL Injection
        # 40014: Cross-Site Scripting
        # 90022: Cross-Site Request Forgery
        # 10045: Cross-Domain JavaScript Inclusion
        # 40003: Path Traversal
        # 40012: Command Injection
        scanners_to_enable = [40018, 40014, 90022, 10045, 40003, 40012]
        for scanner_id in scanners_to_enable:
            zap.ascan.enable_scanners(scanner_id)
        zap.ascan.set_option_thread_per_host(5)

        active_scan_id = zap.ascan.scan(target_url)

        while int(zap.ascan.status(active_scan_id)) < 100:
            active_status = zap.ascan.status(active_scan_id)
            scan_status[scan_id] = {'status': active_status, 'phase': 'active_scanning'}
            time.sleep(2)
        
        zap_alerts = zap.core.alerts(baseurl=target_url)
        alerts = []
        for alert in zap_alerts:
            description = alert.get('alert', 'No description')
            mitigation = MITIGATION_ADVICE.get(description, "No specific mitigation advice available for this alert.")
            alerts.append({
                'risk': alert.get('risk', 'Unknown'),
                'description': description,
                'url': alert.get('url', 'N/A'),
                'mitigation': mitigation
            })
        
        print(f"Active scan completed for {scan_id}. Found {len(alerts)} alerts.")

        # --- SAVE RESULTS & FINISH ---
        scan_results_history[scan_id] = {
            'target_url': target_url,
            'pages': pages,
            'alerts': alerts,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        scan_status[scan_id] = {'status': '100', 'phase': 'complete'}
    
    except Exception as e:
        print(f"Error during scan for {scan_id}: {e}")
        scan_status[scan_id] = {'status': 'Error', 'phase': 'error'}

# ---------------- Routes ----------------
@app.route('/')
def landing():
    return render_template('landing.html')


@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/status')
def status():
    """Endpoint to get the progress of a scan."""
    scan_id = request.args.get('zap_scan_id')
    if scan_id and scan_id in scan_status:
        return jsonify(scan_status.get(scan_id, {'status': 'Not started', 'phase': 'N/A'}))
    return jsonify({'status': 'Not started', 'phase': 'N/A'})


@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('target_url')
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    
    scan_id = str(uuid.uuid4())
    
    # Start the scan process in a new thread immediately
    scan_thread = threading.Thread(target=run_targeted_scan, args=(target_url, scan_id))
    scan_thread.start()
    
    # Immediately redirect to the loading page without waiting
    return redirect(url_for('loading_page', zap_scan_id=scan_id, target_url=target_url))

@app.route('/loading')
def loading_page():
    scan_id = request.args.get('zap_scan_id')
    target_url = request.args.get('target_url')
    return render_template('loading.html', zap_scan_id=scan_id, target_url=target_url)

@app.route('/results/<report_id>')
def show_results(report_id):
    """Route to show final results after the scan is complete."""
    result_data = scan_results_history.get(report_id)
    if not result_data:
        return "Scan report not found.", 404
    
    return render_template('zap_results.html',
                           target_url=result_data['target_url'],
                           pages=result_data['pages'],
                           results=result_data['alerts'],
                           report_id=report_id)

@app.route('/report-list')
def report_list():
    """Route to show a list of all saved scan reports."""
    reports = [
        {'id': scan_id, 'url': data['target_url'], 'timestamp': data['timestamp']}
        for scan_id, data in scan_results_history.items()
    ]
    return render_template('report_list.html', reports=reports)


if __name__ == '__main__':
    app.run(debug=True)


















