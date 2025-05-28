#!/bin/bash

#===============================================================================
# Function: Manage Dashboard Users
#===============================================================================
manage_dashboard_users() {
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    if ! command -v htpasswd &> /dev/null; then echo -e "${RED}ERROR: 'htpasswd' (package apache2-utils) not found.${NC}" >&2; check_dependencies; if ! command -v htpasswd &> /dev/null; then return 1; fi; fi

    # Ensure the auth file exists before entering the loop if we're going to add users
    if [[ ! -f "$TRAEFIK_AUTH_FILE" ]]; then
        echo -e "${YELLOW}INFO: Auth file ${TRAEFIK_AUTH_FILE} does not exist, will be created if needed.${NC}"
    fi


    while true; do
        clear; print_header "Manage Dashboard Users";
        echo -e "| Auth File: ${BOLD}${TRAEFIK_AUTH_FILE}${NC}           |" # Adjusted padding
        echo "+-----------------------------------------+"
        echo -e "|   ${BOLD}1)${NC} Add User                           |";
        echo -e "|   ${BOLD}2)${NC} Remove User                        |";
        echo -e "|   ${BOLD}3)${NC} Change Password                    |";
        echo -e "|   ${BOLD}4)${NC} List Users                         |";
        echo "|-----------------------------------------|";
        echo -e "|   ${BOLD}0)${NC} Back to Main Menu                  |";
        echo "+-----------------------------------------+";
        read -p "Choice [0-4]: " user_choice

        local changes_made=false
        case "$user_choice" in # Quote user_choice
            1) # Add User
                echo "--- Add User ---"
                read -p "New username: " nu; while [[ -z "$nu" ]]; do echo -e "${RED}ERROR: Username cannot be empty.${NC}" >&2; read -p "Username: " nu; done
                # Check if user already exists using grep on the actual file
                if sudo grep -q -E "^${nu}:" "${TRAEFIK_AUTH_FILE}" 2>/dev/null; then echo -e "${YELLOW}WARNING: User '${nu}' already exists.${NC}"; else
                    while true; do read -sp "Password for '${nu}': " np; echo; if [[ -z "$np" ]]; then echo -e "${RED}ERROR: Password cannot be empty.${NC}" >&2; continue; fi; read -sp "Confirm password: " npc; echo; if [[ "$np" == "$npc" ]]; then break; else echo -e "${RED}ERROR: Passwords do not match.${NC}" >&2; fi; done
                    local htpasswd_cmd="sudo htpasswd -b"; if [[ ! -f "$TRAEFIK_AUTH_FILE" ]]; then htpasswd_cmd="sudo htpasswd -cb"; echo -e "${BLUE}INFO: Auth file ${TRAEFIK_AUTH_FILE} will be created.${NC}"; fi
                    if $htpasswd_cmd "${TRAEFIK_AUTH_FILE}" "${nu}" "${np}"; then echo -e "${GREEN}User '${nu}' added.${NC}"; sudo chmod 600 "${TRAEFIK_AUTH_FILE}" 2>/dev/null || echo -e "${YELLOW}WARNING: Could not set permissions for auth file.${NC}" >&2; changes_made=true; else echo -e "${RED}ERROR adding user with htpasswd (Code: $?).${NC}" >&2; fi
                fi; ;;
            2) # Remove User
                echo "--- Remove User ---"; if [[ ! -f "$TRAEFIK_AUTH_FILE" ]]; then echo -e "${RED}ERROR: Auth file ${TRAEFIK_AUTH_FILE} not found.${NC}" >&2; sleep 2; continue; fi
                echo "Current Users:"; users=(); i=1;
                # Read users from the file, skipping comments
                while IFS=: read -r u p; do if [[ ! "$u" =~ ^# ]]; then users+=("$u"); echo "    ${i}) ${u}"; ((i++)); fi; done < <(sudo cat "$TRAEFIK_AUTH_FILE" 2>/dev/null) # Added 2>/dev/null
                if [ ${#users[@]} -eq 0 ]; then echo "No users found in file."; sleep 2; continue; fi; echo "    0) Back"
                read -p "Number of the user to delete: " choice_del; if ! [[ "$choice_del" =~ ^[0-9]+$ ]] || [[ "$choice_del" -lt 0 ]] || [[ "$choice_del" -gt ${#users[@]} ]]; then echo -e "${RED}ERROR: Invalid selection.${NC}" >&2; sleep 2; continue; fi; if [[ "$choice_del" -eq 0 ]]; then echo "Aborting."; continue; fi
                local idx_del=$((choice_del - 1)); local user_del="${users[$idx_del]}"; local confirm_del=false; ask_confirmation "${RED}Really delete user '${user_del}'?${NC}" confirm_del
                if $confirm_del; then
                    # Safer method to delete: Create a temporary file excluding the user
                    local tmp_auth_file=$(mktemp "${TRAEFIK_AUTH_FILE}.tmp.XXXXXX")
                    if sudo grep -v "^${user_del}:" "${TRAEFIK_AUTH_FILE}" > "$tmp_auth_file"; then
                        if sudo mv "$tmp_auth_file" "${TRAEFIK_AUTH_FILE}"; then
                            sudo chmod 600 "${TRAEFIK_AUTH_FILE}" 2>/dev/null || echo -e "${YELLOW}WARNING: Could not set permissions for auth file.${NC}" >&2 # Restore permissions
                            echo -e "${GREEN}User '${user_del}' deleted.${NC}"; changes_made=true;
                        else
                             echo -e "${RED}ERROR: Could not move temporary file back.${NC}" >&2;
                             sudo rm -f "$tmp_auth_file" 2>/dev/null
                        fi
                    else
                        echo -e "${RED}ERROR: Could not filter user from file (grep error).${NC}" >&2;
                        sudo rm -f "$tmp_auth_file" 2>/dev/null
                    fi
                fi; ;;
            3) # Change Password
                 echo "--- Change Password ---"; if [[ ! -f "$TRAEFIK_AUTH_FILE" ]]; then echo -e "${RED}ERROR: Auth file ${TRAEFIK_AUTH_FILE} not found.${NC}" >&2; sleep 2; continue; fi
                 echo "Current Users:"; users=(); i=1;
                 # Read users from the file, skipping comments
                 while IFS=: read -r u p; do if [[ ! "$u" =~ ^# ]]; then users+=("$u"); echo "    ${i}) ${u}"; ((i++)); fi; done < <(sudo cat "$TRAEFIK_AUTH_FILE" 2>/dev/null) # Added 2>/dev/null
                 if [ ${#users[@]} -eq 0 ]; then echo "No users found in file."; sleep 2; continue; fi; echo "    0) Back"
                 read -p "Number of the user whose password should be changed: " choice_ch; if ! [[ "$choice_ch" =~ ^[0-9]+$ ]] || [[ "$choice_ch" -lt 0 ]] || [[ "$choice_ch" -gt ${#users[@]} ]]; then echo -e "${RED}ERROR: Invalid selection.${NC}" >&2; sleep 2; continue; fi; if [[ "$choice_ch" -eq 0 ]]; then echo "Aborting."; continue; fi
                 local idx_ch=$((choice_ch - 1)); local user_ch="${users[$idx_ch]}"
                 local new_pw; local new_pw_c; while true; do read -sp "New password for '${user_ch}': " new_pw; echo; if [[ -z "$new_pw" ]]; then echo -e "${RED}ERROR: Password cannot be empty.${NC}" >&2; continue; fi; read -sp "Confirm new password: " new_pw_c; echo; if [[ "$new_pw" == "$new_pw_c" ]]; then break; else echo -e "${RED}ERROR: Passwords do not match.${NC}" >&2; fi; done
                 if sudo htpasswd -b "${TRAEFIK_AUTH_FILE}" "${user_ch}" "${new_pw}"; then echo -e "${GREEN}Password for '${user_ch}' successfully changed.${NC}"; changes_made=true; else echo -e "${RED}ERROR changing password with htpasswd (Code: $?).${NC}" >&2; fi; ;;
            4) # List Users
                echo "--- User List ---"; if [[ -f "$TRAEFIK_AUTH_FILE" ]]; then echo "Users in ${TRAEFIK_AUTH_FILE}:"; sudo grep -v '^#' "${TRAEFIK_AUTH_FILE}" 2>/dev/null | cut -d: -f1 | sed 's/^/ - /' || echo " (File is empty or error reading)"; else echo -e "${RED}ERROR: Auth file (${TRAEFIK_AUTH_FILE}) not found.${NC}" >&2; fi ;;
            0)
                # git_auto_commit removed
                return 0 ;;
            *) echo -e "${RED}ERROR: Invalid choice.${NC}" >&2 ;;
        esac; echo ""; read -p "... Press Enter for user menu ..." dummy_user
    done
} # End manage_dashboard_users


#===============================================================================
# Function: Show Certificate Details (from ${ACME_TLS_FILE})
#===============================================================================
show_certificate_info() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Show Certificate Details (from ${ACME_TLS_FILE})${NC}"; echo -e "${MAGENTA}==================================================${NC}";
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    if ! command -v jq &> /dev/null; then echo -e "${RED}ERROR: 'jq' required.${NC}" >&2; check_dependencies; if ! command -v jq &> /dev/null; then return 1; fi; fi; if ! command -v openssl &> /dev/null; then echo -e "${RED}ERROR: 'openssl' required.${NC}" >&2; check_dependencies; if ! command -v openssl &> /dev/null; then return 1; fi; fi
    if [[ ! -f "$ACME_TLS_FILE" ]]; then echo -e "${RED}ERROR: ACME storage file (${ACME_TLS_FILE}) not found.${NC}" >&2; return 1; fi

    echo -e "${BLUE}INFO: Reading certificates from ${ACME_TLS_FILE}...${NC}"; echo "--------------------------------------------------";
    local resolver_key; resolver_key=$(sudo jq -r 'keys | .[0]' "${ACME_TLS_FILE}" 2>/dev/null);
    if [[ -z "$resolver_key" || "$resolver_key" == "null" ]]; then echo -e "${RED}ERROR: Could not find ACME resolver key in file or file is empty/invalid.${NC}" >&2; return 1; fi;
    echo -e "${BLUE}Using data for resolver: ${resolver_key}${NC}"
    local cert_count; cert_count=$(sudo jq --arg key "$resolver_key" '.[$key].Certificates | length' "${ACME_TLS_FILE}" 2>/dev/null);
    if [[ -z "$cert_count" || "$cert_count" == "null" ]]; then cert_count=0; fi;
    if [[ "$cert_count" -eq 0 ]]; then echo -e "${YELLOW}No certificates found for resolver '${resolver_key}' in the file.${NC}"; return 0; fi

    echo "Found certificates (${cert_count}):"
    for (( i=0; i<cert_count; i++ )); do
        echo -e "${CYAN}--- Certificate $((i+1)) ---${NC}";
        local main_domain sans cert_base64;
        main_domain=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].domain.main // empty' "${ACME_TLS_FILE}" 2>/dev/null);
        sans=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].domain.sans | if . then map(" - " + .) | join("\n") else empty end' "${ACME_TLS_FILE}" 2>/dev/null);
        cert_base64=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].certificate // empty' "${ACME_TLS_FILE}" 2>/dev/null);

        echo -e "  ${BOLD}Main Domain:${NC} ${main_domain:-N/A}";
        if [[ -n "$sans" ]]; then echo -e "  ${BOLD}Alternatives:${NC}\n${sans}"; fi

        if [[ -n "$cert_base64" ]]; then
            local end_date issuer subject cert_info cert_pem;
            cert_pem=$(echo "$cert_base64" | base64 -d 2>/dev/null);
            if [[ -n "$cert_pem" ]]; then
                # Use openssl to get cert info from PEM format
                cert_info=$(echo "$cert_pem" | openssl x509 -noout -enddate -subject -issuer 2>/dev/null);
                if [[ $? -eq 0 && -n "$cert_info" ]]; then
                    end_date=$(echo "$cert_info" | grep '^notAfter=' | cut -d= -f2-);
                    issuer=$(echo "$cert_info" | grep '^issuer=' | sed 's/issuer=//');
                    subject=$(echo "$cert_info" | grep '^subject=' | sed 's/subject=//');
                    echo -e "  ${BOLD}Valid until:${NC}   ${GREEN}${end_date}${NC}";
                    echo -e "  ${BOLD}Issuer:${NC}      ${issuer}";
                    # echo -e "  ${BOLD}Subject:${NC}     ${subject}"; # Subject often redundant with main_domain/sans
                else
                    echo -e "  ${YELLOW}Could not read certificate details with OpenSSL.${NC}" >&2;
                fi;
            else
                echo -e "  ${YELLOW}Could not decode certificate (base64 error?).${NC}" >&2;
            fi;
        else
             echo -e "  ${YELLOW}No certificate data (certificate field) found in JSON.${NC}";
        fi
    done
    echo "--------------------------------------------------"; echo -e "${YELLOW}HINT: Displayed data comes from ${ACME_TLS_FILE}.${NC}"; echo -e "${YELLOW}         Expiration dates may differ due to automatic renewal.${NC}"; echo "=================================================="; return 0
} # End show_certificate_info

#===============================================================================
# Function: Check Certificate Expiry
#===============================================================================
check_certificate_expiry() {
    local days_threshold=${1:-14} # Default: 14 days
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Check Certificate Expiry (Warning < ${days_threshold} days)${NC}"; echo -e "${MAGENTA}==================================================${NC}";

    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    if ! command -v jq &> /dev/null || ! command -v openssl &> /dev/null || ! command -v date &> /dev/null; then echo -e "${RED}ERROR: 'jq', 'openssl', and 'date' required.${NC}" >&2; check_dependencies; return 1; fi
    if [[ ! -f "$ACME_TLS_FILE" ]]; then echo -e "${RED}ERROR: ACME storage file (${ACME_TLS_FILE}) not found.${NC}" >&2; return 1; fi

    local threshold_seconds=$(( days_threshold * 24 * 60 * 60 ))
    local current_epoch=$(date +%s)
    local warning_found=false
    local error_occurred=false

    echo -e "${BLUE}INFO: Reading certificates from ${ACME_TLS_FILE}...${NC}";
    local resolver_key; resolver_key=$(sudo jq -r 'keys | .[0]' "${ACME_TLS_FILE}" 2>/dev/null);
    if [[ -z "$resolver_key" || "$resolver_key" == "null" ]]; then echo -e "${RED}ERROR: Could not find ACME resolver key or file is empty/invalid.${NC}" >&2; return 1; fi;
    echo -e "${BLUE}Using data for resolver: ${resolver_key}${NC}"
    local cert_count; cert_count=$(sudo jq --arg key "$resolver_key" '.[$key].Certificates | length' "${ACME_TLS_FILE}" 2>/dev/null);
    if [[ -z "$cert_count" || "$cert_count" == "null" ]]; then cert_count=0; fi;
    if [[ "$cert_count" -eq 0 ]]; then echo -e "${YELLOW}No certificates found for resolver '${resolver_key}'.${NC}"; return 0; fi

    echo "Checking ${cert_count} certificates:"
    for (( i=0; i<cert_count; i++ )); do
        # echo -e "${CYAN}--- Certificate $((i+1)) ---${NC}"; # Less verbose
        local main_domain sans cert_base64;
        main_domain=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].domain.main // "N/A"' "${ACME_TLS_FILE}" 2>/dev/null)
        sans=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].domain.sans | if . then map(" - " + .) | join("\n") else empty end' "${ACME_TLS_FILE}" 2>/dev/null)
        cert_base64=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].certificate // empty' "${ACME_TLS_FILE}" 2>/dev/null)

        # echo -e "  ${BOLD}Main Domain:${NC} ${main_domain:-N/A}"; # Less verbose
        # if [[ -n "$sans" ]]; then echo -e "  ${BOLD}Alternatives:${NC}\n${sans}"; fi # Less verbose

        if [[ -n "$cert_base64" ]]; then
            local end_date issuer subject cert_info cert_pem;
            cert_pem=$(echo "$cert_base64" | base64 -d 2>/dev/null);
            if [[ -n "$cert_pem" ]]; then
                 # Extract only the expiry date
                 end_date_str=$(echo "$cert_pem" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
                 if [[ $? -eq 0 && -n "$end_date_str" ]]; then
                    # Convert expiry date to epoch (seconds since 1970)
                    # Note: Date format from openssl can vary! Assumes 'MMM DD HH:MM:SS YYYY GMT' or similar parseable format
                    # Use 'date -d' which is more flexible than 'date -f'
                    end_date_epoch=$(date -d "$end_date_str" +%s 2>/dev/null)
                    if [[ $? -eq 0 ]]; then
                        diff_seconds=$(( end_date_epoch - current_epoch ))
                        days_left=$(( diff_seconds / 86400 )) # 86400 = 24*60*60

                        if [[ "$diff_seconds" -lt 0 ]]; then
                            echo -e " ${RED}- ${main_domain}: EXPIRED ${BOLD}$((-days_left))${NC}${RED} days ago! (${end_date_str})${NC}" >&2
                            warning_found=true
                            error_occurred=true # Expired is an error state
                        elif [[ "$diff_seconds" -lt "$threshold_seconds" ]]; then
                            echo -e " ${YELLOW}- ${main_domain}: Expires in ${BOLD}${days_left}${NC}${YELLOW} days! (${end_date_str})${NC}"
                            warning_found=true
                        else
                             # Optional: Info for valid certificates
                              echo -e " ${GREEN}- ${main_domain}: Valid for ${days_left} days (${end_date_str})${NC}"
                             # : # Do nothing if still valid for a long time
                        fi
                    else
                         echo -e " ${YELLOW}- ${main_domain}: Could not parse expiry date '${end_date_str}'.${NC}" >&2
                         error_occurred=true
                    fi
                 else
                     echo -e " ${YELLOW}- ${main_domain}: Could not extract expiry date from certificate.${NC}" >&2
                     error_occurred=true
                 fi
            else
                 echo -e " ${YELLOW}- ${main_domain}: Could not decode certificate.${NC}" >&2
                 error_occurred=true
            fi
        else
             echo -e " ${YELLOW}- ${main_domain}: No certificate data found in JSON.${NC}";
        fi
    done

    echo "--------------------------------------------------"
    if $error_occurred; then
        echo -e "${RED}Errors occurred during check or expired certificates were found!${NC}" >&2
        return 1
    elif $warning_found; then
         echo -e "${YELLOW}Warning: At least one certificate requires attention!${NC}"
         return 0 # Return 0 for warnings, 1 for errors/expired
    else
        echo -e "${GREEN}No certificates found expiring in less than ${days_threshold} days or already expired.${NC}"
        return 0
    fi
}

#===============================================================================
# Function: Check for Insecure API Configuration
#===============================================================================
check_insecure_api() {
     echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Check for Insecure API Configuration${NC}"; echo -e "${MAGENTA}==================================================${NC}";
     if [[ ! -f "$STATIC_CONFIG_FILE" ]]; then echo -e "${RED}ERROR: Static config not found.${NC}" >&2; return 1; fi

     # Search for 'insecure: true' within the 'api:' block, ignoring comments
     if sudo awk '/^api:/ {flag=1; next} /^[a-zA-Z#]+:/ {if (!/^\s*#/) flag=0} flag && /^\s*insecure:\s*true/' "${STATIC_CONFIG_FILE}" 2>/dev/null | grep -q 'true'; then
         echo -e "${RED}WARNING: Insecure API is enabled! (api.insecure: true in ${STATIC_CONFIG_FILE})${NC}" >&2
         echo -e "${RED}         This allows unauthenticated access to the Traefik API via the 'traefik' EntryPoint (often port 8080).${NC}" >&2
         echo -e "${RED}         It is strongly recommended to set this to 'false' and expose the API via a secured router (like the dashboard).${NC}" >&2
         return 1 # Return error to be considered a problem in Health Check
     else
         echo -e "${GREEN}INFO: API seems securely configured (api.insecure: false or not set).${NC}"
     fi
     echo "=================================================="
     return 0
}

#===============================================================================
# Function: Show Example Fail2Ban Configuration for Traefik Auth
#===============================================================================
generate_fail2ban_config() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Example Fail2Ban Configuration for Traefik Auth${NC}"; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${YELLOW}INFO: Example only! Fail2Ban must be installed and configured separately.${NC}"; echo -e "${YELLOW}      Ensure Traefik Access Logs are in JSON format.${NC}"; echo "--------------------------------------------------"; echo -e "${BOLD}1. Create or adapt filter (/etc/fail2ban/filter.d/traefik-auth.conf):${NC}"; echo "--------------------------------------------------"; cat << EOF
[Definition]
# Searches for JSON log entries with status 401 for the dashboard router
# Note: The RouterName might need adjustment if it's not 'traefik-dashboard-secure@file'.
# Regex adapted for typical Traefik JSON format
failregex = ^{.*"ClientHost":"<HOST>".*"RouterName":"traefik-dashboard-secure@file".*"StatusCode":401.*$
            ^{.*"ClientAddr":"<HOST>".*"RouterName":"traefik-dashboard-secure@file".*"status":401.*$ # Alternative field names
            # Add other variants if necessary, depending on log details
ignoreregex =
# Date/Time Format (if needed, often detected automatically)
# datepattern = %%Y-%%m-%%dT%%H:%%M:%%S(%%z|Z)
EOF
    echo ""; echo "--------------------------------------------------"; echo -e "${BOLD}2. Activate jail (in /etc/fail2ban/jail.local or /etc/fail2ban/jail.d/custom.conf):${NC}"; echo "--------------------------------------------------"; cat << EOF
[traefik-auth]
enabled   = true
port      = http,https # Check ports 80 and 443
filter    = traefik-auth # Name of the filter file without .conf
logpath   = ${TRAEFIK_LOG_DIR}/access.log # Check path to Access Log!
maxretry  = 5  # Number of attempts
findtime  = 600 # Time window for attempts (seconds)
bantime   = 3600 # Ban duration (seconds)
# action = %(action_mwl)s # Example action (blocks and logs)
EOF
    echo "--------------------------------------------------"; echo -e "${YELLOW}IMPORTANT: Adapt paths (logpath), filter name, RouterName in regex, times, ports & actions if necessary!${NC}"; echo "         After changes: 'sudo systemctl restart fail2ban' and check status ('fail2ban-client status traefik-auth')."; echo "=================================================="; return 0
}
