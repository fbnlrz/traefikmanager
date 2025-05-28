#!/bin/bash

# Function for Menu Header
print_header() {
    local title=$1
    local version="2.0.0 (English, Automation)" # Version updated
    clear; echo ""; echo -e "${BLUE}+-----------------------------------------+${NC}"; echo -e "${BLUE}|${NC} ${BOLD}${title}${NC} ${BLUE}|${NC}"; echo -e "${BLUE}|${NC} Version: ${version}  Author: fbnlrz    ${BLUE}|${NC}"; echo -e "${BLUE}|${NC} Based on guide by: phoenyx          ${BLUE}|${NC}"; echo -e "${BLUE}+-----------------------------------------+${NC}"; echo -e "| Current Time: $(date '+%Y-%m-%d %H:%M:%S %Z')    |"; printf "| Traefik Status: %-23s |\n" "${BOLD}$(is_traefik_active && echo "${GREEN}ACTIVE  ${NC}" || echo "${RED}INACTIVE${NC}")${NC}"; echo "+-----------------------------------------+";
}

ask_confirmation() { local p=$1; local v=$2; local r; while true; do read -p "${CYAN}${p}${NC} Type '${BOLD}yes${NC}' or '${BOLD}no${NC}': " r; r=$(echo "$r"|tr '[:upper:]' '[:lower:]'); if [[ "$r" == "yes" ]]; then eval "$v=true"; return 0; elif [[ "$r" == "no" ]]; then eval "$v=false"; return 0; else echo -e "${YELLOW}Unclear answer.${NC}"; fi; done; }
