#!/bin/bash

#===============================================================================
# Function: Check Installed Traefik Version
#===============================================================================
show_traefik_version() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Check Installed Traefik Version${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if [[ -f "$TRAEFIK_BINARY_PATH" ]]; then
        echo "Executing: ${TRAEFIK_BINARY_PATH} version"; echo "--------------------------------------------------";
        if ! sudo "${TRAEFIK_BINARY_PATH}" version 2>&1; then echo -e "${RED}ERROR executing command.${NC}" >&2; return 1; fi;
        echo "--------------------------------------------------";
    else
        echo -e "${RED}ERROR: Traefik binary (${TRAEFIK_BINARY_PATH}) not found.${NC}" >&2;
        return 1;
    fi;
    return 0
}


#===============================================================================
# Function: Check Listening Ports for Traefik (80/443) - Improved Logic
#===============================================================================
check_listening_ports() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Check Listening Ports for Traefik (80/443)${NC}"; echo -e "${MAGENTA}==================================================${NC}";
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    if ! command -v ss &> /dev/null; then echo -e "${RED}ERROR: 'ss' (package iproute2) not found.${NC}" >&2; check_dependencies; if ! command -v ss &> /dev/null; then return 1; fi; fi

    local listens_80=false
    local listens_443=false
    local pid_found=false
    local output_ss=""
    local pid

    # Try to determine PID
    pid=$(systemctl show --property MainPID --value "${TRAEFIK_SERVICE_NAME}" 2>/dev/null || pgrep -f "^${TRAEFIK_BINARY_PATH}.*--configfile=${STATIC_CONFIG_FILE}" || pgrep -o traefik || echo '????')

    echo "Searching with 'ss' for Traefik on Port 80/443...";
    if [[ "$pid" == "????" || -z "$pid" ]]; then
        echo -e "${YELLOW}WARNING: Could not determine Traefik PID uniquely. Checking ports without PID filtering.${NC}" >&2;
        # Check ports without PID, less reliable
        output_ss=$(sudo ss -tlpn '( sport = :80 or sport = :443 )' 2>&1 || echo "ERROR_SS")
    else
        echo "INFO: Checking for process ID(s): ${pid}";
        pid_found=true
        # Get all listening sockets for the PID(s)
        # Build a grep-compatible expression for multiple PIDs if pgrep returns multiple
        local pid_pattern=$(echo "$pid" | sed -e 's/ /|/g' -e 's/^/(/' -e 's/$/)/')
        output_ss=$(sudo ss -tlpn 2>&1 | grep -E "pid=(${pid_pattern})," || echo "") # Capture stderr, return empty string if grep fails/finds nothing
         if [[ "$output_ss" == *"ERROR_SS"* ]]; then # Check if ss itself failed
             echo -e "${RED}ERROR: Could not execute 'ss' successfully.${NC}" >&2; return 1;
         fi
    fi

    echo "--- Result of Port Check ---";
    echo "$output_ss" # Show the ss output

    # Check if Port 80 is in the (potentially filtered) output
    if echo "$output_ss" | grep -q -E ':(80)\s'; then
        listens_80=true
        echo -e " ${GREEN}OK:${NC} Process (PID ${pid:-unknown}) seems to be listening on port 80."
    else
        echo -e " ${RED}ERROR:${NC} Process (PID ${pid:-unknown}) does NOT seem to be listening on port 80!" >&2
    fi

     # Check if Port 443 is in the (potentially filtered) output
    if echo "$output_ss" | grep -q -E ':(443)\s'; then
        listens_443=true
        echo -e " ${GREEN}OK:${NC} Process (PID ${pid:-unknown}) seems to be listening on port 443."
    else
        echo -e " ${RED}ERROR:${NC} Process (PID ${pid:-unknown}) does NOT seem to be listening on port 443!" >&2
    fi

    # Additional hints for problems
    if ! $listens_80 || ! $listens_443; then
         echo -e "${YELLOW}HINT: If Traefik is running but ports are not found:${NC}"
         echo -e "${YELLOW}  - Check the 'address' setting in 'traefik.yaml' under 'entryPoints'.${NC}"
         echo -e "${YELLOW}  - Run 'sudo ss -tlpn | grep -E \":80 |:443 \"' manually.${NC}"
         if ! $pid_found; then
             echo -e "${YELLOW}  - The PID could not be determined, the check was inaccurate.${NC}"
         elif [[ -z "$output_ss" ]]; then
             echo -e "${YELLOW}  - The PID(s) ${pid} was/were found, but it's not listening on the expected ports or 'ss' output is empty.${NC}"
         fi
         echo "==================================================";
         return 1 # Report error if a port is missing
    fi

    echo "==================================================";
    return 0
}


#===============================================================================
# Function: Test Backend Connectivity
#===============================================================================
test_backend_connectivity() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Test Backend Connectivity${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! command -v curl &> /dev/null; then echo -e "${RED}ERROR: 'curl' not found.${NC}" >&2; check_dependencies; if ! command -v curl &> /dev/null; then return 1; fi; fi;
    read -p "Internal URL of the backend (e.g., http://192.168.1.50:8080 or https://service.local): " url; while [[ -z "$url" ]]; do echo -e "${RED}ERROR: URL cannot be empty.${NC}" >&2; read -p "URL: " url; done
    echo "--------------------------------------------------"; echo -e "${BLUE}Testing connection to: ${url}${NC}";
    local opts="-vL --connect-timeout 5 --max-time 10"; # Added max-time
    local insecure_flag=""; local insecure_opt="";
    if [[ "$url" == https://* ]]; then
        local ignore_ssl=false; ask_confirmation "${YELLOW}Ignore backend SSL/TLS certificate (insecure, for self-signed certs)?${NC} " ignore_ssl;
        if $ignore_ssl; then insecure_opt="-k"; insecure_flag="${YELLOW}(SSL certificate check ignored - INSECURE)${NC}"; else insecure_flag="${GREEN}(SSL certificate check active)${NC}"; fi;
        opts="-vL${insecure_opt} --connect-timeout 5 --max-time 10";
    fi;
    echo -e "Executing: curl ${opts} \"${url}\" ${insecure_flag}"; # Quote URL
    echo "--------------------------------------------------";
    local curl_output;
    # Capture stderr and stdout
    if curl_output=$(curl $opts "${url}" 2>&1); then
        local curl_exit_code=0
    else
        local curl_exit_code=$?
    fi
    echo "$curl_output"; echo;
    if [[ $curl_exit_code -eq 0 ]]; then echo "--------------------------------------------------"; echo -e "${GREEN}TEST SUCCESSFUL: Connection OK (Curl Exit Code: 0, see output above).${NC}"; else echo "--------------------------------------------------"; echo -e "${RED}TEST FAILED: Connection to '${url}' not possible (Curl Code: $curl_exit_code).${NC}" >&2; echo -e "${RED}Possible causes: Network problem, Firewall, Service not reachable, wrong URL/Port, SSL problem.${NC}" >&2; return 1; fi; echo "=================================================="; return 0
}

#===============================================================================
# Function: Show Active Configuration (via Traefik API)
#===============================================================================
show_active_config() {
     echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Show Active Configuration (via Traefik API)${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi; if ! command -v curl &> /dev/null; then echo -e "${RED}ERROR: 'curl' not found.${NC}" >&2; check_dependencies; if ! command -v curl &> /dev/null; then return 1; fi; fi; if ! command -v jq &> /dev/null; then echo -e "${RED}ERROR: 'jq' not found.${NC}" >&2; check_dependencies; if ! command -v jq &> /dev/null; then return 1; fi; fi

    local api_url="http://127.0.0.1:8080/api" # Default insecure API address
    local dashboard_domain="";
    # Check if the dashboard dynamic config file exists and extract the domain
    if [[ -f "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" ]]; then
        dashboard_domain=$(grep -oP 'Host\(\`\K[^`]*' "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" 2>/dev/null || true);
    fi

    local api_insecure=false;
    # Check if 'api.insecure: true' is explicitly set in the static config
    if sudo awk '/^api:/ {flag=1; next} /^[a-zA-Z#]+:/ {if (!/^\s*#/) flag=0} flag && /^\s*insecure:\s*true/' "${STATIC_CONFIG_FILE}" 2>/dev/null | grep -q 'true'; then
        api_insecure=true;
    fi

    if $api_insecure; then
        echo -e "${BLUE}INFO: Attempting API via standard URL (${api_url}), as 'insecure: true' seems active.${NC}";
        local api_code; api_code=$(curl --connect-timeout 2 -s -o /dev/null -w "%{http_code}" "${api_url}/rawdata" 2>/dev/null);
        if [[ "$api_code" == "200" ]]; then
            echo -e "${GREEN}INFO: API reachable at ${api_url}.${NC}";
            echo "--- Active HTTP Routers ---";
            if ! curl -s "${api_url}/http/routers" 2>/dev/null | jq '.'; then echo -e "${RED}ERROR querying/parsing routers.${NC}" >&2; fi;
            echo "";
            echo "--- Active HTTP Services ---";
            if ! curl -s "${api_url}/http/services" 2>/dev/null | jq '.'; then echo -e "${RED}ERROR querying/parsing services.${NC}" >&2; fi;
            echo "--------------------------";
        else
            echo -e "${RED}ERROR: API at ${api_url} not reachable (Code: $api_code), although 'insecure: true' is set.${NC}" >&2;
            echo -e "${YELLOW}         Check if the API is actually enabled in ${STATIC_CONFIG_FILE} ('api: { dashboard: true }').${NC}";
            echo -e "${YELLOW}         Ensure no other service is blocking port 8080.${NC}";
            return 1
        fi
    else
        echo -e "${YELLOW}WARNING: API is not in insecure mode ('insecure: false').${NC}";
        if [[ -n "$dashboard_domain" ]]; then
             echo -e "${BLUE}INFO: API is reachable via the Dashboard (HTTPS + Auth) at https://${dashboard_domain}/api.${NC}";
             echo "       Use curl manually with authentication, e.g.:";
             echo "       ${BOLD}curl -u USERNAME https://${dashboard_domain}/api/http/routers | jq${NC}";
             echo "       (Password will be prompted)";
        else
             echo -e "${YELLOW}INFO: Dashboard domain not found or could not be read.${NC}";
             echo "       API is likely only reachable via a manually configured, secured router.";
             echo "       -> Set up a router for 'service: api@internal' or enable";
             echo "          'api: {insecure: true}' in ${STATIC_CONFIG_FILE} (not recommended for production).";
        fi
        return 1; # Return 1 because the active config couldn't be displayed automatically
    fi
    echo "=================================================="; return 0
}

#===============================================================================
# Function: Traefik Health Check
#===============================================================================
health_check() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Traefik Health Check${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi; if ! command -v curl &> /dev/null; then echo -e "${RED}ERROR: 'curl' not found.${NC}" >&2; check_dependencies; if ! command -v curl &> /dev/null; then return 1; fi; fi

    local all_ok=true
    local check_result=0 # Use a variable to track overall success/failure

    echo "--- [1/5] Check systemd Service Status ---"
    if is_traefik_active; then echo -e " ${GREEN}OK:${NC} Traefik systemd service (${TRAEFIK_SERVICE_NAME}) is active."; else echo -e " ${RED}ERROR:${NC} Traefik systemd service is INACTIVE!" >&2; all_ok=false; check_result=1; fi
    echo "--------------------------------------------"

    echo "--- [2/5] Check Listening Ports (80/443) ---"
    # check_listening_ports prints its own output and errors
    if ! check_listening_ports; then
        all_ok=false; check_result=1;
    fi
    # check_listening_ports already prints the separator

    echo "--- [3/5] Check Static Configuration (YAML Syntax) ---"
    # check_static_config prints its own output and errors (yamllint)
    # Note: check_static_config always returns 0, so we check its output for error messages
    local static_check_output
    static_check_output=$(check_static_config 2>&1)
    echo "$static_check_output"
    if echo "$static_check_output" | grep -q "${RED}ERROR:"; then
         # A YAML syntax error is a significant problem
         all_ok=false; check_result=1;
    fi
    # check_static_config already prints the separator

    echo "--- [4/5] Check for Insecure API Configuration ---"
    # check_insecure_api prints its own output and errors, returns 1 if insecure
    if ! check_insecure_api; then
        all_ok=false; check_result=1; # Insecure API is considered a health issue
    fi
    # check_insecure_api already prints the separator


    echo "--- [5/5] Check Dashboard Reachability (if configured) ---"
    local dashboard_domain=""; if [[ -f "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" ]]; then dashboard_domain=$(grep -oP 'Host\(\`\K[^`]*' "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" 2>/dev/null || true); fi
    if [[ -z "$dashboard_domain" ]]; then echo -e " ${YELLOW}INFO:${NC} No Dashboard configuration found, check skipped."; else
        echo "INFO: Checking reachability of https://${dashboard_domain}..."
        # Use -k to allow self-signed/invalid certs for initial reachability check
        local http_code; http_code=$(curl -kLI --connect-timeout 5 --max-time 10 "https://${dashboard_domain}" -s -o /dev/null -w "%{http_code}" 2>/dev/null); local curl_exit_code=$?;
        if [[ $curl_exit_code -ne 0 ]]; then
            echo -e " ${RED}- ERROR:${NC} Connection to https://${dashboard_domain} failed (Curl Code: ${curl_exit_code}). Network? DNS?"; all_ok=false; check_result=1;
        elif [[ "$http_code" == "401" ]]; then
            echo -e " ${GREEN}- OK:${NC}     Dashboard responds with 401 (Authentication required) - this is expected.";
        elif [[ "$http_code" == "200" || "$http_code" == "403" ]]; then
            echo -e " ${GREEN}- OK:${NC}     Dashboard responds (Status: ${http_code}).";
        else
            echo -e " ${RED}- ERROR:${NC} Unexpected HTTP Status: ${http_code}. Check logs!" >&2; all_ok=false; check_result=1;
        fi
    fi
    echo "--------------------------------------------"

    echo ""; echo "--- Overall Health Check Result ---";
    if $all_ok; then echo -e "${GREEN}${BOLD}HEALTH CHECK PASSED: No critical errors found.${NC}"; else echo -e "${RED}${BOLD}HEALTH CHECK FAILED: At least one issue detected! See details above.${NC}" >&2; fi
    echo "=================================================="; return $check_result
}
