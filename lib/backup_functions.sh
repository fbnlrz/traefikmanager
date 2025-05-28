#!/bin/bash

#===============================================================================
# Function: Create Backup
# Argument $1: true for non-interactive mode (cron/timer)
#===============================================================================
backup_traefik() {
    local non_interactive=${1:-false} # Default is interactive

    if ! $non_interactive; then
        echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Backup Traefik Configuration${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    fi

    if ! is_traefik_installed; then
        echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2 # Error to stderr
        return 1
    fi

    if ! sudo mkdir -p "${BACKUP_DIR}"; then
        echo -e "${RED}ERROR: Could not create backup directory ${BACKUP_DIR}.${NC}" >&2
        return 1
    fi
    # Try setting permissions, but continue if it fails
    sudo chmod 700 "${BACKUP_DIR}" 2>/dev/null || echo -e "${YELLOW}WARNING: Could not set permissions for ${BACKUP_DIR} to 700.${NC}" >&2

    local backup_filename="traefik-backup-$(date +%Y%m%d-%H%M%S).tar.gz";
    local full_backup_path="${BACKUP_DIR}/${backup_filename}"

    if $non_interactive; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Creating backup: ${full_backup_path} ..."
    else
        echo "Creating backup: ${full_backup_path} ...";
        echo " Backing up content of: ${TRAEFIK_CONFIG_DIR}";
        echo "(config/, dynamic_conf/, certs/, traefik_auth etc.)"; echo ""
    fi

    # Backup the contents of the directory
    local tar_output
    # Use -C to change directory before archiving contents
    if tar_output=$(sudo tar -czvf "${full_backup_path}" -C "${TRAEFIK_CONFIG_DIR}" . 2>&1); then
        local tar_exit_code=0
    else
        local tar_exit_code=$?
    fi


    if [ $tar_exit_code -eq 0 ]; then
        if $non_interactive; then
             echo "[$(date +'%Y-%m-%d %H:%M:%S')] Backup created successfully: ${full_backup_path}"
             # Log tar output only if needed for debugging
             # echo "$tar_output"
        else
             echo "--------------------------------------------------"; echo -e "${GREEN} Backup successful: ${full_backup_path}${NC}"; sudo ls -lh "${full_backup_path}"; echo "--------------------------------------------------";
        fi
         return 0
    else
         echo -e "${RED}ERROR: Backup failed! (tar Code: ${tar_exit_code})${NC}" >&2
         echo "Tar Output: $tar_output" >&2
         sudo rm -f "${full_backup_path}"; return 1;
    fi
} # End backup_traefik

#===============================================================================
# Function: Restore Backup
#===============================================================================
restore_traefik() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Restore Traefik Configuration${NC}"; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${RED}${BOLD}WARNING:${NC}${RED} Overwrites current configuration in ${TRAEFIK_CONFIG_DIR}!${NC}"; echo "--------------------------------------------------"
    if [ ! -d "$BACKUP_DIR" ]; then echo -e "${RED}ERROR: Backup directory ${BACKUP_DIR} not found.${NC}" >&2; return 1; fi
    echo "Available backups (newest first):"; local files=(); local i=1; local file
    # Use find with -print0 and read -d $'\0' for robustness with filenames, sort by time
    # FIX: Corrected syntax error (removed stray fi;) and unnecessary tr command
    while IFS= read -r -d $'\0' file; do files+=("$(basename "$file")"); echo -e "    ${BOLD}${i})${NC} $(basename "$file") ($(stat -c %y "$file" 2>/dev/null | cut -d'.' -f1))"; ((i++)); done < <(find "${BACKUP_DIR}" -maxdepth 1 -name 'traefik-backup-*.tar.gz' -type f -printf '%T@ %p\0' | sort -znr | cut -z -d' ' -f2-)
    if [ ${#files[@]} -eq 0 ]; then echo -e "${YELLOW}No backups found in ${BACKUP_DIR}.${NC}"; return 1; fi; echo -e "    ${BOLD}0)${NC} Back"; echo "--------------------------------------------------"; local choice; read -p "Number of the backup to restore [0-${#files[@]}]: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 0 ]] || [[ "$choice" -gt ${#files[@]} ]]; then echo -e "${RED}ERROR: Invalid selection.${NC}" >&2; return 1; fi; if [[ "$choice" -eq 0 ]]; then echo "Aborting."; return 1; fi
    local idx=$((choice - 1)); local fname="${files[$idx]}"; local fpath="${BACKUP_DIR}/${fname}"; echo "--------------------------------------------------"; echo -e "${BLUE}Selected backup:${NC} ${fname}"; echo -e "${RED}Target directory (will be OVERWRITTEN):${NC} ${TRAEFIK_CONFIG_DIR}"; echo "--------------------------------------------------"; local restore_confirmed=false; ask_confirmation "${RED}${BOLD}ABSOLUTELY SURE?${NC}${RED} Current configuration in ${TRAEFIK_CONFIG_DIR} will be DELETED and replaced by the backup! This cannot be undone.${NC}" restore_confirmed; if ! $restore_confirmed; then echo "Aborting."; return 1; fi
    echo -e "${BLUE}INFO: Stopping Traefik service before restoring...${NC}"; if is_traefik_active; then manage_service "stop"; sleep 1; if is_traefik_active; then echo -e "${RED}ERROR: Could not stop Traefik. Restore aborted.${NC}" >&2; return 1; fi; else echo "INFO: Traefik was not running."; fi
    echo -e "${BLUE}Restoring backup '${fname}' to ${TRAEFIK_CONFIG_DIR} ...${NC}";

    # Ensure the target directory exists before extracting into it
    if ! sudo mkdir -p "${TRAEFIK_CONFIG_DIR}"; then
        echo -e "${RED}ERROR: Could not create target directory ${TRAEFIK_CONFIG_DIR}.${NC}" >&2;
        return 1
    fi

    # Extract directly into the target directory with --overwrite
    if sudo tar -xzvf "${fpath}" -C "${TRAEFIK_CONFIG_DIR}" --overwrite; then
        local tar_exit_code=$?
        if [ $tar_exit_code -eq 0 ]; then
             echo -e "${GREEN}Backup restored successfully.${NC}"; echo "Setting permissions...";
             # Set permissions for known sensitive files AFTER extracting
             if [[ -f "${ACME_TLS_FILE}" ]]; then
                 sudo chmod 600 "${ACME_TLS_FILE}" 2>/dev/null || echo -e "${YELLOW}WARNING: Could not set permissions for ACME TLS file (${ACME_TLS_FILE}).${NC}" >&2;
             fi
             if [[ -f "${TRAEFIK_AUTH_FILE}" ]]; then
                 sudo chmod 600 "${TRAEFIK_AUTH_FILE}" 2>/dev/null || echo -e "${YELLOW}WARNING: Could not set permissions for auth file (${TRAEFIK_AUTH_FILE}).${NC}" >&2;
             fi
             # git_auto_commit removed

             echo "--------------------------------------------------"; echo -e "${GREEN}INFO: Restore finished.${NC}"; local start_confirmed=false; ask_confirmation "Start Traefik now?" start_confirmed; if $start_confirmed; then manage_service "start"; else echo "INFO: Traefik not started."; fi;
             return 0
        else
             echo -e "${RED}ERROR: Restore failed! (tar Code: ${tar_exit_code})${NC}" >&2; echo -e "${RED} State of ${TRAEFIK_CONFIG_DIR} might be inconsistent!${NC}" >&2; return 1;
        fi
    else
        local tar_exit_code=$?
        echo -e "${RED}ERROR: Restore failed! (tar could not be executed, Code: ${tar_exit_code})${NC}" >&2; echo -e "${RED}         State of ${TRAEFIK_CONFIG_DIR} might be inconsistent!${NC}" >&2; return 1;
    fi
} # End restore_traefik
