#!/bin/bash

#===============================================================================
# Function: Setup/Modify Automatic Backup
#===============================================================================
setup_autobackup() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Setup/Modify Automatic Backup${NC}"; echo -e "${MAGENTA}==================================================${NC}";

    local service_file="/etc/systemd/system/${AUTOBACKUP_SERVICE}"
    local timer_file="/etc/systemd/system/${AUTOBACKUP_TIMER}"
    local overwrite_confirmed=false

    if [[ -f "$service_file" || -f "$timer_file" ]]; then
        echo -e "${YELLOW}WARNING: Autobackup service/timer files already exist.${NC}"
        ask_confirmation "${YELLOW}Overwrite existing autobackup files and reconfigure?${NC}" overwrite_confirmed
        if ! $overwrite_confirmed; then
            echo "Aborting."; return 1
        fi
        echo -e "${BLUE}INFO: Overwriting existing configuration...${NC}"
    fi

    # --- Service File Content ---
    echo -e "${BLUE}Creating Systemd service file (${AUTOBACKUP_SERVICE})...${NC}"
    if ! sudo tee "$service_file" > /dev/null <<EOF
[Unit]
Description=Traefik Automatic Backup Service
Documentation=file://${SCRIPT_PATH}
After=network.target

[Service]
Type=oneshot
# Executes the main script in non-interactive backup mode
ExecStart=${SCRIPT_PATH} --run-backup
User=root
Group=root
StandardOutput=append:${AUTOBACKUP_LOG}
StandardError=append:${AUTOBACKUP_LOG}
WorkingDirectory=/tmp

[Install]
WantedBy=multi-user.target
EOF
    then
        echo -e "${RED}ERROR: Could not create service file '${service_file}'.${NC}" >&2
        return 1
    fi
    sudo chmod 644 "$service_file"

    # --- Timer File Content ---
    echo -e "${BLUE}Creating Systemd timer file (${AUTOBACKUP_TIMER})...${NC}"
    # TODO: Maybe ask user for frequency? Defaulting to daily.
    local backup_schedule="daily" # e.g., daily, hourly, weekly, *-*-* 03:00:00
    local random_delay="1h"
    echo -e "${CYAN}INFO: Backup will run daily by default (with up to ${random_delay} delay).${NC}"
    echo -e "${CYAN}      You can adjust the schedule later in '${timer_file}' under '[Timer] OnCalendar='.${NC}"

    if ! sudo tee "$timer_file" > /dev/null <<EOF
[Unit]
Description=Traefik Automatic Backup Timer (runs ${AUTOBACKUP_SERVICE})
Documentation=file://${SCRIPT_PATH}
# Ensures the timer knows about the service
Requires=${AUTOBACKUP_SERVICE}

[Timer]
# Schedule for execution (e.g., daily at a random time between 00:00 and 01:00)
OnCalendar=${backup_schedule}
# Runs the backup if the server was offline at the scheduled time
Persistent=true
# Spreads the load by delaying the start by a random amount of time
RandomizedDelaySec=${random_delay}
Unit=${AUTOBACKUP_SERVICE}

[Install]
WantedBy=timers.target
EOF
    then
        echo -e "${RED}ERROR: Could not create timer file '${timer_file}'.${NC}" >&2
        sudo rm -f "$service_file" # Cleanup service file
        return 1
    fi
    sudo chmod 644 "$timer_file"

    # --- Enable and Start Timer ---
    echo -e "${BLUE}Enabling and starting the timer...${NC}"
    if ! sudo systemctl daemon-reload; then
        echo -e "${RED}ERROR: systemctl daemon-reload failed.${NC}" >&2
        sudo rm -f "$service_file" "$timer_file" # Cleanup
        return 1
    fi
    if ! sudo systemctl enable --now "${AUTOBACKUP_TIMER}"; then
        echo -e "${RED}ERROR: Could not enable/start timer '${AUTOBACKUP_TIMER}'.${NC}" >&2
        echo -e "${YELLOW}      Check 'systemctl status ${AUTOBACKUP_TIMER}' and 'journalctl -u ${AUTOBACKUP_TIMER}'.${NC}" >&2
        sudo rm -f "$service_file" "$timer_file" # Cleanup
        return 1
    fi

    echo "--------------------------------------------------"
    echo -e "${GREEN}Automatic backup set up successfully!${NC}"
    echo " Timer status: $(systemctl is-active ${AUTOBACKUP_TIMER})"
    echo " Next run: $(systemctl list-timers "${AUTOBACKUP_TIMER}" | grep NEXT | awk '{print $4, $5, $6, $7}')"
    echo " Logs will be written to ${AUTOBACKUP_LOG}."
    echo "=================================================="
    return 0
}

#===============================================================================
# Function: Remove Automatic Backup
#===============================================================================
remove_autobackup() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Remove Automatic Backup${NC}"; echo -e "${MAGENTA}==================================================${NC}";

    local service_file="/etc/systemd/system/${AUTOBACKUP_SERVICE}"
    local timer_file="/etc/systemd/system/${AUTOBACKUP_TIMER}"
    local remove_confirmed=false

    if [[ ! -f "$service_file" && ! -f "$timer_file" ]]; then
        echo -e "${YELLOW}INFO: Autobackup service/timer files not found. Nothing to do.${NC}"
        return 0
    fi

    ask_confirmation "${RED}Really stop, disable, and delete the autobackup service and timer?${NC}" remove_confirmed
    if ! $remove_confirmed; then
        echo "Aborting."; return 1
    fi

    echo -e "${BLUE}Stopping and disabling timer...${NC}"
    sudo systemctl stop "${AUTOBACKUP_TIMER}" 2>/dev/null || true
    sudo systemctl disable "${AUTOBACKUP_TIMER}" 2>/dev/null || true

    echo -e "${BLUE}Removing Systemd unit files...${NC}"
    sudo rm -f "$timer_file" "$service_file"

    echo -e "${BLUE}Reloading Systemd...${NC}"
    sudo systemctl daemon-reload 2>/dev/null || true
    sudo systemctl reset-failed "${AUTOBACKUP_TIMER}" "${AUTOBACKUP_SERVICE}" 2>/dev/null || true

    echo "--------------------------------------------------"
    echo -e "${GREEN}Automatic backup removed successfully.${NC}"
    echo -e "${YELLOW}The log file (${AUTOBACKUP_LOG}) was NOT deleted.${NC}"
    echo "=================================================="
    return 0
}

#===============================================================================
# Function: Setup Dedicated IP Logging
#===============================================================================
setup_ip_logging() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Setup Dedicated IP Logging${NC}"; echo -e "${MAGENTA}==================================================${NC}";

    # Check dependency
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}ERROR: 'jq' is required for IP logging.${NC}" >&2
        check_dependencies # Attempt to install
        if ! command -v jq &> /dev/null; then
            echo -e "${RED}ERROR: 'jq' could not be installed. Aborting.${NC}" >&2
            return 1
        fi
    fi

    # --- Check if Traefik access log is JSON (Improved awk) ---
    local access_log_format
    access_log_format=$(sudo awk '
        /^accessLog:/ {in_block=1; next}
        /^[a-zA-Z#]+:/ && !/^\s*#/ {if (in_block) in_block=0} # Exit block on next top-level key
        in_block && /^\s*format:\s*([a-zA-Z]+)/ { # Match format line inside block, ignore comments
            match($0, /^\s*format:\s*([a-zA-Z]+)/, arr);
            print arr[1]; # Print the captured format
            found=1;
            exit; # Found it, stop processing
        }
        END {if (!found) print "common"} # Default if not found
    ' "${STATIC_CONFIG_FILE}" 2>/dev/null)

    if [[ "$access_log_format" != "json" ]]; then
        echo -e "${RED}ERROR: Traefik Access Log Format is not set to 'json' in ${STATIC_CONFIG_FILE} (or could not be read)!${NC}" >&2
        echo -e "${RED}        The IP logging script requires JSON logs. Please correct the Traefik configuration.${NC}" >&2
        echo -e "${RED}        (Found value: '${access_log_format}')" >&2 # Show what was found
        return 1
    fi
    # --- End Check ---


    local service_file="/etc/systemd/system/${IPLOGGER_SERVICE}"
    local timer_file="/etc/systemd/system/${IPLOGGER_SERVICE%.service}.timer" # Derive timer name
    local overwrite_confirmed=false

    if [[ -f "$service_file" || -f "$timer_file" || -f "$IPLOGGER_HELPER_SCRIPT" || -f "$IPLOGGER_LOGROTATE_CONF" ]]; then
        echo -e "${YELLOW}WARNING: IP Logger files (Service/Timer/Script/Logrotate) already partially exist.${NC}"
        ask_confirmation "${YELLOW}Overwrite existing IP Logger files and reconfigure?${NC}" overwrite_confirmed
        if ! $overwrite_confirmed; then
            echo "Aborting."; return 1
        fi
        echo -e "${BLUE}INFO: Overwriting existing configuration...${NC}"
    fi

    # --- Helper Script Content ---
    echo -e "${BLUE}Creating helper script (${IPLOGGER_HELPER_SCRIPT})...${NC}"
    if ! sudo tee "$IPLOGGER_HELPER_SCRIPT" > /dev/null <<EOF
#!/bin/bash
# Helper script to extract client IPs from Traefik JSON Access Logs

# Configuration
ACCESS_LOG="${TRAEFIK_LOG_DIR}/access.log"
IP_LOG="${IP_LOG_FILE}"
JQ_COMMAND="/usr/bin/jq" # Use full path for robustness

# Check if jq exists
if [ ! -x "\${JQ_COMMAND}" ]; then
    echo "[ERROR] jq command not found or not executable at \${JQ_COMMAND}" >&2
    exit 1
fi

# Check if Access Log exists and is readable
if [ ! -r "\${ACCESS_LOG}" ]; then
    echo "[INFO] Traefik access log '\${ACCESS_LOG}' not found or not readable. Skipping run." >&2
    # Exit 0 here, as the service might run before the log is created
    # or if Traefik is temporarily stopped. Don't want the service to fail constantly.
    exit 0
fi

# Ensure the target log directory exists
mkdir -p "$(dirname "\${IP_LOG}")"

# Extract ClientHost (or ClientAddr as fallback) and redirect to the IP log file
# Filters only entries that have 'ClientHost' or 'ClientAddr'
# Adds a timestamp
# tail -n +1 -f would make this a long-running service, but we use a timer
# So we process the whole file (or use state tracking - simpler: process whole file)
# Using jq 'select' to filter and format output
# Note: Processing the whole file repeatedly can be inefficient for large logs.
# A more advanced script might track the last processed line number or timestamp.
# This simple version processes the whole file each time the timer runs.
echo "[INFO] Processing \${ACCESS_LOG}..."
if ! \${JQ_COMMAND} -r --arg date_fmt "+%Y-%m-%d %H:%M:%S" \
    'select(.ClientHost != null or .ClientAddr != null) | now | strftime($date_fmt) + " " + (.ClientHost // .ClientAddr // "N/A")' \
    "\${ACCESS_LOG}" >> "\${IP_LOG}"; then
    echo "[ERROR] jq processing failed for \${ACCESS_LOG}" >&2
    exit 1 # Exit with error if jq fails
fi

# Optional: Deduplicate the IP log file periodically? Not here, keep it simple.

echo "[INFO] IP extraction finished."
exit 0
EOF
    then
        echo -e "${RED}ERROR: Could not create helper script '${IPLOGGER_HELPER_SCRIPT}'.${NC}" >&2
        return 1
    fi
    sudo chmod +x "$IPLOGGER_HELPER_SCRIPT"

    # --- Service File Content ---
    echo -e "${BLUE}Creating Systemd service file (${IPLOGGER_SERVICE})...${NC}"
    if ! sudo tee "$service_file" > /dev/null <<EOF
[Unit]
Description=Traefik IP Address Logger Service (runs helper script)
Documentation=file://${SCRIPT_PATH}
After=traefik.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${IPLOGGER_HELPER_SCRIPT}
User=root # Needs access to /var/log/traefik and potentially /usr/local/sbin
Group=root
# Optional: Add sandboxing if desired, but needs careful testing with jq/file access
# PrivateTmp=true
# ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
    then
        echo -e "${RED}ERROR: Could not create service file '${service_file}'.${NC}" >&2
        sudo rm -f "$IPLOGGER_HELPER_SCRIPT" # Cleanup
        return 1
    fi
    sudo chmod 644 "$service_file"

    # --- Timer File Content ---
    echo -e "${BLUE}Creating Systemd timer file (${timer_file})...${NC}"
    local log_schedule="*:0/15" # Every 15 minutes
    local log_random_delay="1m"
    echo -e "${CYAN}INFO: IP Logging will run every 15 minutes by default.${NC}"
    echo -e "${CYAN}      You can adjust the schedule later in '${timer_file}'.${NC}"

    if ! sudo tee "$timer_file" > /dev/null <<EOF
[Unit]
Description=Traefik IP Address Logger Timer (runs ${IPLOGGER_SERVICE})
Documentation=file://${SCRIPT_PATH}
Requires=${IPLOGGER_SERVICE}

[Timer]
# Schedule for execution (e.g., every 15 minutes)
OnCalendar=${log_schedule}
Persistent=true
RandomizedDelaySec=${log_random_delay}
Unit=${IPLOGGER_SERVICE}

[Install]
WantedBy=timers.target
EOF
    then
        echo -e "${RED}ERROR: Could not create timer file '${timer_file}'.${NC}" >&2
        sudo rm -f "$IPLOGGER_HELPER_SCRIPT" "$service_file" # Cleanup
        return 1
    fi
    sudo chmod 644 "$timer_file"

    # --- Logrotate Configuration ---
    echo -e "${BLUE}Creating Logrotate configuration (${IPLOGGER_LOGROTATE_CONF})...${NC}"
    if ! sudo tee "$IPLOGGER_LOGROTATE_CONF" > /dev/null <<EOF
${IP_LOG_FILE} {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    su root adm
}
EOF
    then
        echo -e "${RED}ERROR: Could not create logrotate file '${IPLOGGER_LOGROTATE_CONF}'.${NC}" >&2
        sudo rm -f "$IPLOGGER_HELPER_SCRIPT" "$service_file" "$timer_file" # Cleanup
        return 1
    fi
    sudo chmod 644 "$IPLOGGER_LOGROTATE_CONF"

    # --- Enable and Start Timer ---
    echo -e "${BLUE}Enabling and starting the timer...${NC}"
    if ! sudo systemctl daemon-reload; then
        echo -e "${RED}ERROR: systemctl daemon-reload failed.${NC}" >&2
        sudo rm -f "$IPLOGGER_HELPER_SCRIPT" "$service_file" "$timer_file" "$IPLOGGER_LOGROTATE_CONF" # Cleanup
        return 1
    fi
    if ! sudo systemctl enable --now "${timer_file}"; then
        echo -e "${RED}ERROR: Could not enable/start timer '${timer_file}'.${NC}" >&2
        echo -e "${YELLOW}      Check 'systemctl status ${timer_file}' and 'journalctl -u ${IPLOGGER_SERVICE}'.${NC}" >&2
        sudo rm -f "$IPLOGGER_HELPER_SCRIPT" "$service_file" "$timer_file" "$IPLOGGER_LOGROTATE_CONF" # Cleanup
        return 1
    fi

    echo "--------------------------------------------------"
    echo -e "${GREEN}Dedicated IP Logging set up successfully!${NC}"
    echo " Helper Script: ${IPLOGGER_HELPER_SCRIPT}"
    echo " Service: ${service_file}"
    echo " Timer: ${timer_file} (runs every 15 min)"
    echo " IP Log File: ${IP_LOG_FILE}"
    echo " Logrotate Config: ${IPLOGGER_LOGROTATE_CONF}"
    echo " Timer Status: $(systemctl is-active ${timer_file})"
    echo " Next Run: $(systemctl list-timers "${timer_file}" | grep NEXT | awk '{print $4, $5, $6, $7}')"
    echo "=================================================="
    return 0
}

#===============================================================================
# Function: Remove Dedicated IP Logging
#===============================================================================
remove_ip_logging() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Remove Dedicated IP Logging${NC}"; echo -e "${MAGENTA}==================================================${NC}";

    local service_file="/etc/systemd/system/${IPLOGGER_SERVICE}"
    local timer_file="/etc/systemd/system/${IPLOGGER_SERVICE%.service}.timer" # Derive timer name
    local remove_confirmed=false

    if [[ ! -f "$service_file" && ! -f "$timer_file" && ! -f "$IPLOGGER_HELPER_SCRIPT" && ! -f "$IPLOGGER_LOGROTATE_CONF" ]]; then
        echo -e "${YELLOW}INFO: IP Logger files not found. Nothing to do.${NC}"
        return 0
    fi

    ask_confirmation "${RED}Really remove the IP Logger service/timer, helper script, and logrotate config?${NC}" remove_confirmed
    if ! $remove_confirmed; then
        echo "Aborting."; return 1
    fi

    echo -e "${BLUE}Stopping and disabling timer...${NC}"
    sudo systemctl stop "${timer_file}" 2>/dev/null || true
    sudo systemctl disable "${timer_file}" 2>/dev/null || true

    echo -e "${BLUE}Removing files...${NC}"
    sudo rm -f "$timer_file" "$service_file" "$IPLOGGER_HELPER_SCRIPT" "$IPLOGGER_LOGROTATE_CONF"

    echo -e "${BLUE}Reloading Systemd...${NC}"
    sudo systemctl daemon-reload 2>/dev/null || true
    sudo systemctl reset-failed "${timer_file}" "${IPLOGGER_SERVICE}" 2>/dev/null || true

    echo "--------------------------------------------------"
    echo -e "${GREEN}Dedicated IP Logging removed successfully.${NC}"
    echo -e "${YELLOW}The log file (${IP_LOG_FILE}) was NOT deleted.${NC}"
    echo "=================================================="
    return 0
}
