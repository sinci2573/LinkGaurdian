from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import json
import os

app = Flask(__name__)
CORS(app)

VIRUSTOTAL_API_KEY = "667bdef1d47597bbeb87dd2bfa8345126a1b5b325e82a9fa1bbf4fb1221e4436"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

def get_virustotal_result(url):
    try:
        # Step 1: Encode the URL
        url_id = requests.utils.quote(url, safe='')
        
        # Step 2: Submit for scanning
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = requests.post(VIRUSTOTAL_URL, headers=headers, data={"url": url})
        response_data = response.json()

        analysis_id = response_data["data"]["id"]

        # Step 3: Retrieve the result
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_response = requests.get(analysis_url, headers=headers)
        result_data = analysis_response.json()

        stats = result_data["data"]["attributes"]["stats"]
        malicious_count = stats.get("malicious", 0)

        if malicious_count > 0:
            return False, "⚠️ Detected as malicious by VirusTotal."
        else:
            return True, "✅ No threats found on VirusTotal."
    except Exception as e:
        return False, f"Error checking URL: {str(e)}"
    
def save_to_history(url, message, safe):
    history_entry = {"url": url, "message": message, "safe": safe}
    history_file = "history.json"

    if os.path.exists(history_file):
        with open(history_file, "r") as f:
            try:
                history = json.load(f)
            except json.JSONDecodeError:
                history = []
    else:
        history = []

    history.insert(0, history_entry)  # Add to top

    with open(history_file, "w") as f:
        json.dump(history, f, indent=2)


@app.route('/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get("url", "").lower()

    # Step 1: VirusTotal check
    vt_safe, vt_msg = get_virustotal_result(url)

    # Step 2: Heuristics check
    heuristic_msg = ""
    safe = vt_safe

    if len(url) > 75:
        heuristic_msg += "🔎 Very long URL. "
        safe = False
    if url.count('.') > 3:
        heuristic_msg += "🔎 Suspicious number of subdomains. "
        safe = False
    if any(url.endswith(tld) for tld in ['.tk', '.ml', '.ru', '.ga']):
        heuristic_msg += "🔎 Suspicious top-level domain. "
        safe = False
    if any(kw in url for kw in ['login', 'verify', 'secure', 'update', 'account']):
        heuristic_msg += "🔎 Contains sensitive-looking keywords. "
        safe = False

    final_msg = vt_msg
    if heuristic_msg:
        final_msg += "\n" + heuristic_msg

    save_to_history(url, final_msg, safe)

    return jsonify({"safe": safe, "message": final_msg})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000, debug=True)


