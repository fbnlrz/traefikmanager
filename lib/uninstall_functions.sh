#!/bin/bash

#===============================================================================
# Function: Uninstall Traefik
#===============================================================================
uninstall_traefik() {
    echo ""; echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}"; echo -e "${RED}!! ATTENTION: UNINSTALLATION! EVERYTHING WILL BE GONE! NO GOING BACK!      !!${NC}"; echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}"; echo "Are you sure? All that work..."; echo " - Service? Gone."; echo " - Binary? Gone."; echo " - Configs (${TRAEFIK_CONFIG_DIR})? All gone."; echo " - Logs (${TRAEFIK_LOG_DIR})? Gone too."; echo ""; echo "Apt packages will remain though."; echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}"; echo ""
    if ! is_traefik_installed; then echo -e "${YELLOW}INFO: Traefik does not seem to be (fully) installed.${NC}"; local c=false; ask_confirmation "${YELLOW}Attempt to clean up known remnants (files/folders) anyway?${NC}" c; if ! $c; then echo "Aborting."; return 1; fi; else local d=false; ask_confirmation "${RED}${BOLD}Last chance:${NC}${RED} Really DELETE EVERYTHING related to Traefik (configs, binary, logs, service files)? This is irreversible!${NC}" d; if ! $d; then echo "Aborting."; return 1; fi; fi; echo ""; echo -e "${BLUE}>>> Starting uninstallation...${NC}";
    # Remove automation units - Call implemented functions
    echo -e "${BLUE}[0/8] Stopping & removing automation units...${NC}"; # Numbering adjusted
    remove_autobackup || echo -e "${YELLOW}WARNING: Error removing autobackup units.${NC}" >&2
    remove_ip_logging || echo -e "${YELLOW}WARNING: Error removing IP logging units/scripts.${NC}" >&2
    # remove_autopull removed

    echo "[1/8] Stopping service..."; if systemctl is-active --quiet "${TRAEFIK_SERVICE_NAME}"; then sudo systemctl stop "${TRAEFIK_SERVICE_NAME}" && echo " Stopped." || echo -e "${RED}ERROR: Could not stop service.${NC}" >&2; else echo " Was not running or service unknown."; fi;
    echo "[2/8] Disabling autostart..."; if systemctl is-enabled --quiet "${TRAEFIK_SERVICE_NAME}"; then sudo systemctl disable "${TRAEFIK_SERVICE_NAME}" && echo " Disabled." || echo -e "${RED}ERROR: Could not disable autostart.${NC}" >&2; else echo " Was not enabled or service unknown."; fi;
    echo "[3/8] Removing service file..."; if [[ -f "${TRAEFIK_SERVICE_FILE}" ]]; then sudo rm -f "${TRAEFIK_SERVICE_FILE}" && echo " Deleted: ${TRAEFIK_SERVICE_FILE}" || echo -e "${RED}ERROR: Could not delete service file.${NC}" >&2; else echo " Not found: ${TRAEFIK_SERVICE_FILE}"; fi;
    echo "[4/8] Reloading Systemd..."; sudo systemctl daemon-reload && echo " Reloaded." || echo -e "${RED}ERROR: daemon-reload failed.${NC}" >&2; sudo systemctl reset-failed "${TRAEFIK_SERVICE_NAME}" &> /dev/null || true;
    echo "[5/8] Removing binary..."; if [[ -f "${TRAEFIK_BINARY_PATH}" ]]; then sudo rm -f "${TRAEFIK_BINARY_PATH}" && echo " Deleted: ${TRAEFIK_BINARY_PATH}" || echo -e "${RED}ERROR: Could not delete binary.${NC}" >&2; else echo " Not found: ${TRAEFIK_BINARY_PATH}"; fi;
    echo "[6/8] Removing configs..."; if [[ -d "${TRAEFIK_CONFIG_DIR}" ]]; then sudo rm -rf "${TRAEFIK_CONFIG_DIR}" && echo " Deleted: ${TRAEFIK_CONFIG_DIR}" || echo -e "${RED}ERROR: Could not delete config directory.${NC}" >&2; else echo " Not found: ${TRAEFIK_CONFIG_DIR}"; fi;
    echo "[7/8] Removing logs..."; if [[ -d "${TRAEFIK_LOG_DIR}" ]]; then sudo rm -rf "${TRAEFIK_LOG_DIR}" && echo " Deleted: ${TRAEFIK_LOG_DIR} (incl. ip_access.log etc.)" || echo -e "${RED}ERROR: Could not delete log directory.${NC}" >&2; else echo " Not found: ${TRAEFIK_LOG_DIR}"; fi;
    echo "[8/8] Removing helper scripts & logrotate configs..."; # Combined
     if [[ -f "${IPLOGGER_HELPER_SCRIPT}" ]]; then sudo rm -f "${IPLOGGER_HELPER_SCRIPT}" && echo " Deleted: ${IPLOGGER_HELPER_SCRIPT}" || echo -e "${RED}ERROR: Could not delete IP Logger script.${NC}" >&2; else echo " Not found: ${IPLOGGER_HELPER_SCRIPT}"; fi;
     # AUTOPULL_HELPER_SCRIPT removed
     if [[ -f "${IPLOGGER_LOGROTATE_CONF}" ]]; then sudo rm -f "${IPLOGGER_LOGROTATE_CONF}" && echo " Deleted: ${IPLOGGER_LOGROTATE_CONF}" || echo -e "${RED}ERROR: Could not delete IP Logger logrotate config.${NC}" >&2; else echo " Not found: ${IPLOGGER_LOGROTATE_CONF}"; fi;
    echo ""; echo -e "${GREEN}===========================================${NC}"; echo -e "${GREEN} Uninstallation (or cleanup attempt) finished.${NC}"; echo -e "${YELLOW} Hopefully that was the right thing to do.${NC}"; echo -e "${GREEN}===========================================${NC}"; echo " Consider running 'sudo apt purge apache2-utils jq curl ... && sudo apt autoremove'"; echo "==========================================="; return 0
} # End uninstall_traefik
