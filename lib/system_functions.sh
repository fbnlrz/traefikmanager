#!/bin/bash

#===============================================================================
# Function: Get Log Lines (Non-Interactive)
# Arguments: $1: log_type, $2: num_lines (optional, default 100)
# Outputs: Log lines to stdout or an error message.
# Returns: 0 on success, 1 on error.
#===============================================================================
get_log_lines() {
    local log_type=$1
    local num_lines=${2:-100} # Default to 100 lines if not specified

    # Validate num_lines is a positive integer
    if ! [[ "$num_lines" =~ ^[0-9]+$ && "$num_lines" -gt 0 ]]; then
        echo "ERROR: Number of lines must be a positive integer. Got: '${num_lines}'"
        return 1
    fi

    local f=""
    case "$log_type" in
       traefik) f="${TRAEFIK_LOG_DIR}/traefik.log"; if [[ -f "$f" ]]; then sudo tail -n "${num_lines}" "$f"; else echo "ERROR: Log (${f}) not found."; return 1; fi ;;
       access) f="${TRAEFIK_LOG_DIR}/access.log"; if [[ -f "$f" ]]; then sudo tail -n "${num_lines}" "$f"; else echo "ERROR: Log (${f}) not found."; return 1; fi ;;
       ip_access) f="${IP_LOG_FILE}"; if [[ -f "$f" ]]; then sudo tail -n "${num_lines}" "$f"; else echo "ERROR: Log (${f}) not found (IP Logging maybe not active?)."; return 1; fi ;;
       journal) sudo journalctl -u "${TRAEFIK_SERVICE_NAME}" -n "${num_lines}" --no-pager || { echo "ERROR: journalctl for traefik failed."; return 1; } ;;
       autobackup) sudo journalctl -u "${AUTOBACKUP_SERVICE}" -n "${num_lines}" --no-pager || { echo "ERROR: journalctl for autobackup failed."; return 1; } ;;
       ip_logger) sudo journalctl -u "${IPLOGGER_SERVICE}" -n "${num_lines}" --no-pager || { echo "ERROR: journalctl for ip_logger failed."; return 1; } ;;
       autobackup_file) f="${AUTOBACKUP_LOG}"; if [[ -f "$f" ]]; then sudo tail -n "${num_lines}" "$f"; else echo "ERROR: Log (${f}) not found (Autobackup maybe not active?)."; return 1; fi ;;
       *) echo "ERROR: Log type '$log_type' unknown."; return 1 ;;
    esac
    return 0
}


#===============================================================================
# Function: Manage Traefik Service
#===============================================================================
manage_service() {
    local action=$1; echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Traefik Service: Action '${action}' attempting...${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi; if ! [[ -f "${TRAEFIK_SERVICE_FILE}" ]]; then echo -e "${RED}ERROR: Service file not found (${TRAEFIK_SERVICE_FILE}).${NC}" >&2; return 1; fi
    case "$action" in # Quote action
        start)
            if is_traefik_active; then echo -e "${YELLOW}INFO: Already running.${NC}"; else
                if sudo systemctl start "${TRAEFIK_SERVICE_NAME}"; then
                    sleep 1;
                    if is_traefik_active; then echo -e "${GREEN}Started.${NC}"; else echo -e "${RED}ERROR: Start failed!${NC}" >&2; return 1; fi
                else
                    echo -e "${RED}ERROR: systemctl start failed!${NC}" >&2; return 1;
                fi
            fi
            ;;
        stop)
            if ! is_traefik_active; then echo -e "${YELLOW}INFO: Was not running.${NC}"; else
                if sudo systemctl stop "${TRAEFIK_SERVICE_NAME}"; then
                    sleep 1;
                    if ! is_traefik_active; then echo -e "${GREEN}Stopped.${NC}"; else echo -e "${RED}ERROR: Stop failed!${NC}" >&2; return 1; fi
                else
                    echo -e "${RED}ERROR: systemctl stop failed!${NC}" >&2; return 1;
                fi
            fi
            ;;
        restart)
            echo "Restarting...";
            if sudo systemctl restart "${TRAEFIK_SERVICE_NAME}"; then
                sleep 2;
                if is_traefik_active; then echo -e "${GREEN}Restart successful.${NC}"; else echo -e "${RED}ERROR: Was not running after restart!${NC}" >&2; return 1; fi
            else
                echo -e "${RED}ERROR: systemctl restart failed!${NC}" >&2; return 1;
            fi
            ;;
        status)
            echo "Status:";
            if ! sudo systemctl status "${TRAEFIK_SERVICE_NAME}" --no-pager -l; then echo -e "${YELLOW}WARNING: Status check failed!${NC}" >&2; return 1; fi # Return 1 if status fails
            ;;
        *) echo -e "${RED}ERROR: Action '$action' unknown.${NC}" >&2; return 1 ;;
    esac; echo "=================================================="; return 0
} # End manage_service


#===============================================================================
# Function: View Logs
#===============================================================================
view_logs() {
    local log_type=$1; echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Show Logs: ${log_type}${NC}"; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${CYAN}INFO: Press Ctrl+C to exit.${NC}"; echo "--------------------------------------------------"; sleep 1
    local f="" # Variable for file paths
    case "$log_type" in # Quote log_type
       traefik) f="${TRAEFIK_LOG_DIR}/traefik.log"; if [[ -f "$f" ]]; then sudo tail -n 100 -f "$f"; else echo -e "${RED}ERROR: Log (${f}) not found.${NC}" >&2; return 1; fi ;;
       access) f="${TRAEFIK_LOG_DIR}/access.log"; if [[ -f "$f" ]]; then sudo tail -n 100 -f "$f"; else echo -e "${RED}ERROR: Log (${f}) not found.${NC}" >&2; return 1; fi ;;
       ip_access) f="${IP_LOG_FILE}"; if [[ -f "$f" ]]; then sudo tail -n 100 -f "$f"; else echo -e "${RED}ERROR: Log (${f}) not found (IP Logging maybe not active?).${NC}" >&2; return 1; fi ;;
       journal) sudo journalctl -u "${TRAEFIK_SERVICE_NAME}" -n 100 -f || { echo -e "${RED}ERROR: journalctl failed.${NC}" >&2; return 1; } ;;
       autobackup) sudo journalctl -u "${AUTOBACKUP_SERVICE}" -n 100 -f || { echo -e "${RED}ERROR: journalctl failed.${NC}" >&2; return 1; } ;;
       ip_logger) sudo journalctl -u "${IPLOGGER_SERVICE}" -n 100 -f || { echo -e "${RED}ERROR: journalctl failed.${NC}" >&2; return 1; } ;;
       autobackup_file) f="${AUTOBACKUP_LOG}"; if [[ -f "$f" ]]; then sudo tail -n 100 -f "$f"; else echo -e "${RED}ERROR: Log (${f}) not found (Autobackup maybe not active?).${NC}" >&2; return 1; fi ;;
       # autopull_file removed
       *) echo -e "${RED}ERROR: Log type '$log_type' unknown.${NC}" >&2; return 1 ;; esac;
    echo "--------------------------------------------------"; echo -e "${CYAN}Log view finished.${NC}"; return 0
} # End view_logs
