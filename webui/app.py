from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
import os # For a more robust secret key generation
import subprocess
import yaml  # For parsing YAML files
import glob  # For listing files
import re # For parsing the output of show_certificate_info

app = Flask(__name__)
# It's crucial to set a secret key for session management.
# For development, a fixed key is okay. For production, use a random, secure key.
app.secret_key = os.urandom(24) # Generates a random key each time app starts

# WARNING: Hardcoded credentials are for development/demonstration ONLY.
# In a real application, use a database and hashed passwords.
USERS = {
    "admin": "password123"
}

# --- Script Path Definition ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) # webui directory
TRAEFIK_MANAGER_SCRIPT = os.path.join(os.path.dirname(SCRIPT_DIR), 'traefikmanager.sh') # Path to traefikmanager.sh in parent dir
TRAEFIK_DYNAMIC_CONF_DIR = "/opt/traefik/dynamic_conf" # As defined in traefikmanager.sh

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in_user' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Helper Function to Run Script Commands ---
def run_script_command(command_parts):
    try:
        # Use sudo for actions that require it
        process = subprocess.run(command_parts, capture_output=True, text=True, check=False, timeout=30)
        return {
            "success": process.returncode == 0,
            "returncode": process.returncode,
            "stdout": process.stdout.strip(),
            "stderr": process.stderr.strip()
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out", "stderr": "", "stdout": "", "returncode": -1 }
    except Exception as e:
        return {"success": False, "error": str(e), "stderr": "", "stdout": "", "returncode": -1 }

# --- Standard Routes ---
@app.route('/')
@login_required
def home():
    return render_template('home.html', username=session.get('logged_in_user'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in USERS and USERS[username] == password:
            session['logged_in_user'] = username
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in_user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- API Routes for Service Management ---
@app.route('/api/service/status', methods=['GET'])
@login_required
def service_status():
    # The traefikmanager.sh script's manage_service('status') handles sudo internally if needed.
    result = run_script_command(['bash', TRAEFIK_MANAGER_SCRIPT, '--service-action', 'status'])
    return jsonify(result)

@app.route('/api/service/start', methods=['POST'])
@login_required
def service_start():
    # Actions like start/stop/restart require sudo to execute the script itself, 
    # which then handles its own potential sudo for systemctl.
    result = run_script_command(['sudo', 'bash', TRAEFIK_MANAGER_SCRIPT, '--service-action', 'start'])
    if result['success']:
        flash('Traefik service start command issued.', 'success')
    else:
        flash(f"Error starting Traefik: {result.get('stderr', result.get('error', 'Unknown error'))}", 'danger')
    return jsonify(result)

@app.route('/api/service/stop', methods=['POST'])
@login_required
def service_stop():
    result = run_script_command(['sudo', 'bash', TRAEFIK_MANAGER_SCRIPT, '--service-action', 'stop'])
    if result['success']:
        flash('Traefik service stop command issued.', 'success')
    else:
        flash(f"Error stopping Traefik: {result.get('stderr', result.get('error', 'Unknown error'))}", 'danger')
    return jsonify(result)

@app.route('/api/service/restart', methods=['POST'])
@login_required
def service_restart():
    result = run_script_command(['sudo', 'bash', TRAEFIK_MANAGER_SCRIPT, '--service-action', 'restart'])
    if result['success']:
        flash('Traefik service restart command issued.', 'success')
    else:
        flash(f"Error restarting Traefik: {result.get('stderr', result.get('error', 'Unknown error'))}", 'danger')
    return jsonify(result)

# --- API Routes for Route/Service Configuration Management ---
@app.route('/api/routes', methods=['GET'])
@login_required
def list_routes():
    routes = []
    excluded_files = ['middlewares.yml', 'traefik_dashboard.yml']
    try:
        # Ensure the directory exists before listing
        if not os.path.isdir(TRAEFIK_DYNAMIC_CONF_DIR):
            return jsonify(success=True, routes=[], message="Dynamic configuration directory not found.")

        yml_files = glob.glob(os.path.join(TRAEFIK_DYNAMIC_CONF_DIR, '*.yml'))
        for file_path in yml_files:
            filename = os.path.basename(file_path)
            if filename in excluded_files:
                continue

            service_name = filename.replace('.yml', '')
            route_info = {'name': service_name, 'filename': filename, 'rule': 'N/A', 'services': []}

            try:
                with open(file_path, 'r') as f:
                    # It's good practice to handle potential read errors or empty files
                    file_content_str = f.read()
                    if not file_content_str.strip(): # Check if file is empty or only whitespace
                        route_info['error'] = f"File {filename} is empty."
                        routes.append(route_info)
                        continue
                    
                    content = yaml.safe_load(file_content_str) # Use the content string
                    
                    if content and 'http' in content:
                        if 'routers' in content['http'] and content['http']['routers']:
                            # Iterate through routers to find the first one with a rule
                            for router_data in content['http']['routers'].values():
                                if isinstance(router_data, dict) and 'rule' in router_data:
                                    route_info['rule'] = router_data.get('rule', 'N/A')
                                    break 
                        if 'services' in content['http'] and content['http']['services']:
                            # Iterate through services to find the first one with servers
                            for svc_data in content['http']['services'].values():
                                if isinstance(svc_data, dict) and 'loadBalancer' in svc_data and 'servers' in svc_data['loadBalancer']:
                                    route_info['services'] = [server.get('url', 'N/A') for server in svc_data['loadBalancer']['servers'] if isinstance(server, dict)]
                                    break 
            except yaml.YAMLError as ye:
                route_info['error'] = f"Error parsing YAML in {filename}: {str(ye)}"
            except Exception as e:
                route_info['error'] = f"Error reading or processing {filename}: {str(e)}"
            
            routes.append(route_info)
        return jsonify(success=True, routes=routes)
    except Exception as e:
        # Log this exception server-side for debugging
        app.logger.error(f"Error listing route files: {str(e)}")
        return jsonify(success=False, error=str(e), message="Error listing route files."), 500

@app.route('/api/routes/<string:filename>', methods=['GET'])
@login_required
def get_route_content(filename):
    # Basic security: ensure filename is just a name and not a path
    if '..' in filename or filename.startswith('/') or not filename.endswith('.yml'):
        return jsonify(success=False, error="Invalid filename or not a .yml file."), 400

    file_path = os.path.join(TRAEFIK_DYNAMIC_CONF_DIR, filename)
    
    # Double check it's not an excluded file - defensive coding
    excluded_files = ['middlewares.yml', 'traefik_dashboard.yml']
    if filename in excluded_files:
         return jsonify(success=False, error="Access to this configuration file is restricted."), 403

    if not os.path.exists(file_path): # Check after constructing full path
        return jsonify(success=False, error="File not found."), 404

    try:
        with open(file_path, 'r') as f:
            content_str = f.read()
        
        parsed_yaml = None
        error_parsing = None
        try:
            parsed_yaml = yaml.safe_load(content_str)
        except yaml.YAMLError as ye:
            error_parsing = str(ye)

        return jsonify(success=True, filename=filename, raw_content=content_str, parsed_content=parsed_yaml, parsing_error=error_parsing)
    except Exception as e:
        app.logger.error(f"Error reading file {filename}: {str(e)}")
        return jsonify(success=False, error=str(e), message=f"Error reading file {filename}."), 500

@app.route('/api/routes/add', methods=['POST'])
@login_required
def api_add_route():
    data = request.get_json()
    if not data:
        return jsonify(success=False, error="Invalid JSON payload"), 400

    service_name = data.get('service_name')
    domain = data.get('domain')
    backend_target = data.get('backend_target') # e.g., "192.168.1.10:80"
    backend_https_str = str(data.get('backend_https', False)).lower() # "true" or "false"
    skip_verify_str = str(data.get('skip_verify', False)).lower()   # "true" or "false"

    if not all([service_name, domain, backend_target]):
        return jsonify(success=False, error="Missing required fields: service_name, domain, backend_target"), 400

    command = [
        'sudo', 'bash', TRAEFIK_MANAGER_SCRIPT, '--add-route',
        '--service-name', service_name,
        '--domain', domain,
        '--backend-target', backend_target,
        '--backend-https', backend_https_str,
        '--skip-verify', skip_verify_str
    ]
    
    result = run_script_command(command)
    if result['success']:
        flash(f"Route '{service_name}' add command issued. {result.get('stdout', '')}", 'success')
    else:
        flash(f"Error adding route '{service_name}': {result.get('stderr','') or result.get('error','')}", 'danger')
    return jsonify(result)

@app.route('/api/routes/remove', methods=['POST'])
@login_required
def api_remove_route():
    data = request.get_json()
    if not data:
        return jsonify(success=False, error="Invalid JSON payload"), 400
    
    filename = data.get('filename')
    if not filename:
        return jsonify(success=False, error="Missing required field: filename"), 400

    # Basic validation for filename
    if '..' in filename or not filename.endswith('.yml') or '/' in filename:
        return jsonify(success=False, error="Invalid filename format."), 400

    command = [
        'sudo', 'bash', TRAEFIK_MANAGER_SCRIPT, '--remove-route', '--filename', filename
    ]
    result = run_script_command(command)

    if result['success']:
        flash(f"Route file '{filename}' remove command issued. {result.get('stdout', '')}", 'success')
    else:
        flash(f"Error removing route '{filename}': {result.get('stderr','') or result.get('error','')}", 'danger')
    return jsonify(result)

# --- API Route for SSL Certificate Information ---
@app.route('/api/ssl/certificates', methods=['GET'])
@login_required
def api_get_ssl_certificates():
    # The `show_certificate_info` function in traefikmanager.sh is designed to be run with sudo
    # if it needs to access restricted files (like acme.json).
    # The run_script_command helper doesn't prepend sudo by default, so ensure the script handles it
    # or adjust here if direct sudo is needed for the script invocation itself.
    # For --show-cert-info, the script itself handles sudo for jq/openssl if needed.
    command = ['bash', TRAEFIK_MANAGER_SCRIPT, '--show-cert-info']
    result = run_script_command(command)

    if not result['success']:
        # If script itself failed (e.g., ACME file not found, jq/openssl missing)
        # The error message might be in stderr or stdout if the script echoes errors.
        error_details = result.get('stderr') if result.get('stderr') else result.get('stdout', 'No specific error output from script.')
        if "ERROR:" in error_details: # Prioritize stderr if it contains ERROR:
             return jsonify(success=False, error="Failed to retrieve certificate information from script.", details=error_details), 500
        # If no "ERROR:" in stderr, but script failed, it could be an execution issue before script logic.
        return jsonify(success=False, error="Script execution failed or reported an issue.", details=error_details), 500


    raw_output = result['stdout']
    certificates = []
    
    ansi_escape = re.compile(r'\x1B(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_output = ansi_escape.sub('', raw_output)

    # Check for known "no certificates" or "error" messages from the script
    if "No certificates found" in clean_output:
        return jsonify(success=True, certificates=[], message="No certificates found.")
    if "Could not find ACME resolver key" in clean_output or "ACME storage file" in clean_output and "not found" in clean_output :
        return jsonify(success=True, certificates=[], message=clean_output) # Script correctly reports no file/key
    if "ERROR:" in clean_output.upper() and not "INFO: Reading certificates" in clean_output : # Check for script-level errors not caught by returncode
        # This case is if the script ran (returncode 0) but internally printed an error message we should surface.
        # We avoid catching "INFO: Reading certificates" as an error.
        return jsonify(success=False, error="Error reported by certificate script.", details=clean_output)


    # Split into blocks for each certificate
    # Each certificate block is assumed to start with "--- Certificate X ---"
    # and contain lines for Main Domain, Alternatives, Valid until, Issuer.
    
    # First, try to find the resolver line to remove it if it's there
    lines = clean_output.splitlines()
    processed_lines = []
    for line in lines:
        # Filter out headers/footers/info lines from the script itself
        if "INFO: Reading certificates from" in line or \
           "Using data for resolver:" in line or \
           "Found certificates (" in line or \
           "Show Certificate Details" in line.upper() or \
           "==================================================" in line or \
           "--------------------------------------------------" in line or \
           "HINT: Displayed data comes from" in line or \
           "Expiration dates may differ" in line:
            continue
        processed_lines.append(line)
    
    clean_output_for_parsing = "\n".join(processed_lines)
    
    # Regex to capture certificate blocks.
    # It looks for "--- Certificate X ---" then captures everything until the next one or end of string.
    cert_blocks_matches = re.finditer(r'--- Certificate \d+ ---\s*\n(.*?)(?=\n--- Certificate \d+ ---|\Z)', clean_output_for_parsing, re.DOTALL)

    for match in cert_blocks_matches:
        block_content = match.group(1).strip()
        current_cert = {'main_domain': 'N/A', 'alternatives': [], 'issuer': 'N/A', 'valid_until': 'N/A'}
        
        for line in block_content.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("Main Domain:"):
                current_cert['main_domain'] = line.replace("Main Domain:", "").strip()
            elif line.startswith("- "): # This indicates an alternative name
                current_cert['alternatives'].append(line.replace("- ", "").strip())
            elif "Alternatives:" in line: # Header for alternatives, can be skipped
                continue
            elif line.startswith("Valid until:"):
                current_cert['valid_until'] = line.replace("Valid until:", "").strip()
            elif line.startswith("Issuer:"):
                current_cert['issuer'] = line.replace("Issuer:", "").strip()
        
        if current_cert['main_domain'] != 'N/A': # Only add if we found a main domain
             certificates.append(current_cert)

    # This is a fallback if the regex splitting didn't work but there's content.
    # It's less reliable.
    if not certificates and clean_output_for_parsing.strip() and "No certificates found" not in clean_output_for_parsing:
        # Attempt line-by-line parsing if block splitting failed
        current_cert_fallback = None
        for line in clean_output_for_parsing.splitlines():
            line = line.strip()
            if not line: continue

            if line.startswith("Main Domain:"):
                if current_cert_fallback and current_cert_fallback.get('main_domain') != 'N/A':
                    certificates.append(current_cert_fallback)
                current_cert_fallback = {'main_domain': line.replace("Main Domain:", "").strip(), 'alternatives': [], 'issuer': 'N/A', 'valid_until': 'N/A'}
            elif line.startswith("- ") and current_cert_fallback:
                current_cert_fallback['alternatives'].append(line.replace("- ", "").strip())
            elif line.startswith("Valid until:") and current_cert_fallback:
                current_cert_fallback['valid_until'] = line.replace("Valid until:", "").strip()
            elif line.startswith("Issuer:") and current_cert_fallback:
                current_cert_fallback['issuer'] = line.replace("Issuer:", "").strip()
        
        if current_cert_fallback and current_cert_fallback.get('main_domain') != 'N/A' and current_cert_fallback not in certificates :
            certificates.append(current_cert_fallback)

    # If after all parsing attempts, certificates list is empty but there was output from script
    # that wasn't a "no certs" message, it indicates a parsing failure or unexpected format.
    if not certificates and clean_output_for_parsing.strip() and not ("No certificates found" in clean_output_for_parsing or "Could not find ACME resolver key" in clean_output_for_parsing):
        app.logger.error(f"Failed to parse certificate output. Cleaned output for parsing: \n{clean_output_for_parsing}")
        return jsonify(success=False, error="Could not parse certificate information from script output.", details=raw_output)

    return jsonify(success=True, certificates=certificates)

# --- API Route for Log Viewing ---
@app.route('/api/logs/<string:log_type>', methods=['GET'])
@login_required
def api_get_logs(log_type):
    lines = request.args.get('lines', '100') # Default to 100 lines
    
    if not lines.isdigit():
        return jsonify(success=False, error="Invalid 'lines' parameter: must be a number."), 400

    command = [
        'bash', TRAEFIK_MANAGER_SCRIPT, 
        '--view-log', log_type, 
        '--lines', lines
    ]
    
    result = run_script_command(command)

    if result['success']:
        log_content = result['stdout']
        # Check if the script itself reported an error (e.g., log file not found)
        # These errors are printed to stdout by the get_log_lines function.
        if log_content.strip().startswith("ERROR:"):
            return jsonify(success=False, error=log_content.strip(), log_type=log_type)
        return jsonify(success=True, log_type=log_type, lines=lines, content=log_content)
    else:
        # This case handles script execution failures (e.g., script not found, permissions for script itself)
        # or if the script explicitly exits with non-zero (which get_log_lines does on error).
        # If get_log_lines returns 1, its error message is in stdout, which run_script_command captures.
        error_message = result.get('stdout') if result.get('stdout', '').strip().startswith("ERROR:") else result.get('stderr', 'Failed to retrieve logs.')
        if not error_message and result.get('error'): # Fallback to 'error' field if stdout/stderr are empty
            error_message = result.get('error')

        return jsonify(success=False, error=error_message or "Failed to retrieve logs.", log_type=log_type), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
