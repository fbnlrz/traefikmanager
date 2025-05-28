#!/bin/bash

# --- Helper Functions ---
check_root() { if [[ $EUID -ne 0 ]]; then echo -e "${RED}ERROR: Root privileges (sudo) required!${NC}" >&2; exit 1; fi; }
is_traefik_installed() { if [[ -f "$TRAEFIK_BINARY_PATH" && -d "$TRAEFIK_CONFIG_DIR" && -f "$STATIC_CONFIG_FILE" ]]; then return 0; else return 1; fi; }
is_traefik_active() { systemctl is-active --quiet "${TRAEFIK_SERVICE_NAME}"; return $?; }

check_dependencies() {
    local missing_pkgs=(); local pkgs_to_install=()
    # git removed
    local dependencies=( "jq:jq" "curl:curl" "htpasswd:apache2-utils" "nc:netcat-openbsd" "openssl:openssl" "stat:coreutils" "sed:sed" "grep:grep" "awk:gawk" "tar:tar" "find:findutils" "ss:iproute2" "yamllint:yamllint")
    echo -e "${BLUE}Checking required additional tools...${NC}"
    local jq_needed=false

    # Check if the IP Logger service unit exists (even if inactive)
    if systemctl list-unit-files --no-pager 2>/dev/null | grep -q "^${IPLOGGER_SERVICE}"; then jq_needed=true; fi

    for item in "${dependencies[@]}"; do local cmd="${item%%:*}"; local pkg="${item##*:}";
        if ! command -v "$cmd" &> /dev/null; then
           local is_needed=true # Needed by default
           if [[ "$cmd" == "yamllint" ]]; then
               is_needed=false # Only optional
           elif [[ "$cmd" == "jq" ]] && ! $jq_needed; then
               is_needed=false # Only needed if IP Logger is active (or service unit exists)
           fi

            if $is_needed && [[ ! " ${pkgs_to_install[@]} " =~ " ${pkg} " ]]; then
                 pkgs_to_install+=("$pkg");
                 missing_pkgs+=("$cmd ($pkg)");
            fi
        fi
    done

    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        echo -e "${YELLOW}WARNING: The following commands/packages are missing for some core functions:${NC}"; printf "  - %s\n" "${missing_pkgs[@]}"; local install_confirmed=false; ask_confirmation "${YELLOW}Install the missing packages (${pkgs_to_install[*]}) now (sudo apt install...)?${NC} " install_confirmed
        if $install_confirmed; then local install_list=$(echo "${pkgs_to_install[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '); echo -e "${BLUE}Installing: ${install_list}...${NC}"; if ! sudo apt-get update || ! sudo apt-get install -y $install_list; then echo -e "${RED}ERROR: Could not install packages.${NC}" >&2; else echo -e "${GREEN}Additional packages installed.${NC}"; fi; else echo -e "${YELLOW}INFO: Missing packages not installed.${NC}"; fi; echo "--------------------------------------------------"; sleep 1
    else echo -e "${GREEN}All required core additional tools are present.${NC}"; fi

    if ! command -v yamllint &> /dev/null; then
         echo -e "${YELLOW}INFO: Optional tool 'yamllint' not found (useful for Menu 2->4). Install: sudo apt install yamllint${NC}"
    fi
    # Check jq separately if IP logger service exists
    if $jq_needed && ! command -v jq &> /dev/null; then
        echo -e "${RED}ERROR: 'jq' is required for the IP logger (service exists) but is not installed!${NC}" >&2
        echo -e "${RED}        Please install: sudo apt install jq ${NC}" >&2
        # return 1 # Optional: Exit script if critical dependency is missing
    fi
}
