#!/bin/bash

#===============================================================================
# Traefik Management Script for Debian 12
#
# Version:      2.0.0 (English Translation, Automation Implemented)
# Author:       fbnlrz (Fixes/Translation by AI Assistant)
# Based on:     Guide by phoenyx (Many thanks!)
# Date:         2025-04-13 (Last Update: 2025-04-24)
#
# Description:  Comprehensive script for managing a Traefik v3 instance.
#               Installation, configuration, services, logs, backup, autobackup,
#               IP logging, updates, etc. (WITHOUT Git functions)
#===============================================================================

# --- Global Configuration Variables ---
TRAEFIK_SERVICE_FILE="/etc/systemd/system/traefik.service"
TRAEFIK_BINARY_PATH="/usr/local/bin/traefik"
TRAEFIK_CONFIG_DIR="/opt/traefik" # Main directory for Backup/Restore
TRAEFIK_LOG_DIR="/var/log/traefik"
TRAEFIK_SERVICE_NAME="traefik.service"
TRAEFIK_DYNAMIC_CONF_DIR="${TRAEFIK_CONFIG_DIR}/dynamic_conf"
TRAEFIK_CERTS_DIR="${TRAEFIK_CONFIG_DIR}/certs"
TRAEFIK_AUTH_FILE="${TRAEFIK_CONFIG_DIR}/traefik_auth"
ACME_TLS_FILE="${TRAEFIK_CERTS_DIR}/tls_letsencrypt.json"    # Main ACME file
STATIC_CONFIG_FILE="${TRAEFIK_CONFIG_DIR}/config/traefik.yaml"
MIDDLEWARES_FILE="${TRAEFIK_DYNAMIC_CONF_DIR}/middlewares.yml"
BACKUP_BASE_DIR="/var/backups"
BACKUP_DIR="${BACKUP_BASE_DIR}/traefik"
IP_LOG_FILE="${TRAEFIK_LOG_DIR}/ip_access.log" # Path for IP log
SCRIPT_PATH="$(realpath "$0")" # Path to the current script

DEFAULT_TRAEFIK_VERSION="v3.3.5" # Adjust default version here if desired
GITHUB_REPO="traefik/traefik" # For Update Check

# --- Systemd Unit Names ---
AUTOBACKUP_SERVICE="traefik-autobackup.service"
AUTOBACKUP_TIMER="traefik-autobackup.timer"
AUTOBACKUP_LOG="/var/log/traefik_autobackup.log" # File log for autobackup script output
IPLOGGER_SERVICE="traefik-ip-logger.service"
IPLOGGER_HELPER_SCRIPT="/usr/local/sbin/traefik-extract-ips.sh"
IPLOGGER_LOGROTATE_CONF="/etc/logrotate.d/traefik-ip-logger"
# AUTOPULL_* variables removed

# --- Colors for Output (optional) ---
if [ -t 1 ] && command -v tput &> /dev/null; then ncolors=$(tput colors); if [ -n "$ncolors" ] && [ "$ncolors" -ge 8 ]; then RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4); MAGENTA=$(tput setaf 5); CYAN=$(tput setaf 6); WHITE=$(tput setaf 7); BOLD=$(tput bold); NC=$(tput sgr0); else RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; WHITE=""; BOLD=""; NC=""; fi; else RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; WHITE=""; BOLD=""; NC=""; fi


# --- Argument Parsing for Non-Interactive Mode ---
declare -g non_interactive_mode=false
declare -g service_action_arg=""
declare -g add_route_flag=false
declare -g service_name_arg=""
declare -g domain_arg=""
declare -g backend_target_arg="" # Expected format "ip:port" or "host:port"
declare -g backend_https_arg="false"
declare -g skip_verify_arg="false"
declare -g remove_route_flag=false
declare -g filename_arg=""
declare -g show_cert_info_flag=false
declare -g view_log_flag=false
declare -g log_type_arg=""
declare -g lines_arg="100" # Default

# Using a loop for more robust argument parsing
# Store original arguments to restore later if needed, though for these actions we exit.
ORIGINAL_ARGS=("$@") 
POSITIONAL_ARGS=() 

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-backup)
            non_interactive_mode=true
            # No shift needed here if it's the only arg or handled before this loop
            # For this subtask, we assume it's processed correctly by existing logic if this loop is placed early
            shift # past argument
            ;;
        --service-action)
            if [[ -n "$2" && ( "$2" == "start" || "$2" == "stop" || "$2" == "restart" || "$2" == "status" ) ]]; then
                non_interactive_mode=true
                service_action_arg="$2"
                shift 2 # past argument and value
            else
                echo -e "${RED}ERROR: --service-action requires a valid action (start, stop, restart, status)." >&2
                exit 1
            fi
            ;;
        --add-route)
            add_route_flag=true
            non_interactive_mode=true
            shift # past argument
            ;;
        --service-name)
            service_name_arg="$2"
            shift 2 # past argument and value
            ;;
        --domain)
            domain_arg="$2"
            shift 2
            ;;
        --backend-target)
            backend_target_arg="$2"
            shift 2
            ;;
        --backend-https)
            backend_https_arg="$2"
            shift 2
            ;;
        --skip-verify)
            skip_verify_arg="$2"
            shift 2
            ;;
        --remove-route)
            remove_route_flag=true
            non_interactive_mode=true
            shift
            ;;
        --filename)
            filename_arg="$2"
            shift 2
            ;;
        --show-cert-info)
            show_cert_info_flag=true
            non_interactive_mode=true # To bypass menu
            shift # past argument
            ;;
        --view-log)
            view_log_flag=true
            non_interactive_mode=true # To bypass menu
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                log_type_arg="$2"
                shift 2 # past argument and value
            else
                echo -e "${RED}ERROR: --view-log requires a log_type argument.${NC}" >&2
                exit 1
            fi
            ;;
        --lines)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                lines_arg="$2"
                shift 2 # past argument and value
            else
                echo -e "${RED}ERROR: --lines requires a number argument.${NC}" >&2
                exit 1
            fi
            ;;
        *)
            # Collect positional arguments if any, or unknown options
            POSITIONAL_ARGS+=("$1")
            shift # past argument
            ;;
    esac
done
# Restore positional arguments if the script were to continue for other purposes
# For the new flags (--add-route, --remove-route), the script will exit.
# For existing flags like --run-backup, they are typically handled by checking $1 directly.
# This loop is more for extracting keyed arguments.
# If --run-backup or --service-action was the first argument, it would have been shifted away
# before this loop in a more complex setup. Here, we handle them within.
# Let's re-evaluate the original $1 for --run-backup for compatibility with existing logic.
# If non_interactive_mode is true, one of the flags must have been set.
# The logic below the sourcing will handle the execution and exit.

# --- Source Library Files ---
# Determine the directory of the script
SCRIPT_DIR="${SCRIPT_PATH%/*}"

# Source all library files
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/lib/ui_helpers.sh"
source "${SCRIPT_DIR}/lib/install_functions.sh"
source "${SCRIPT_DIR}/lib/config_functions.sh"
source "${SCRIPT_DIR}/lib/service_functions.sh"
source "${SCRIPT_DIR}/lib/security_functions.sh"
source "${SCRIPT_DIR}/lib/system_functions.sh"
source "${SCRIPT_DIR}/lib/backup_functions.sh"
source "${SCRIPT_DIR}/lib/automation_functions.sh"
source "${SCRIPT_DIR}/lib/diagnostics_functions.sh"
source "${SCRIPT_DIR}/lib/maintenance_functions.sh"
source "${SCRIPT_DIR}/lib/uninstall_functions.sh"

# --- MAIN MENU LOGIC ---
# (Must be after all function definitions)

# Execute non-interactive actions if requested
if $non_interactive_mode; then
    # Re-check original $1 for --run-backup as the loop consumes arguments
    if [[ "${ORIGINAL_ARGS[0]}" == "--run-backup" ]]; then
        if declare -F backup_traefik > /dev/null; then
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] Running non-interactive backup via ${SCRIPT_PATH}..."
            backup_traefik true
            exit_code=$?
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] Non-interactive backup finished with exit code ${exit_code}."
            exit $exit_code
        else
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] CRITICAL ERROR: backup_traefik function not defined for non-interactive mode." >&2
            exit 1
        fi
    elif [[ -n "$service_action_arg" ]]; then # --service-action was parsed
        if declare -F manage_service > /dev/null; then
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] Executing direct service action: $service_action_arg via ${SCRIPT_PATH}..."
            manage_service "$service_action_arg"
            exit_code=$?
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] Direct service action finished with exit code ${exit_code}."
            exit $exit_code
        else
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] CRITICAL ERROR: manage_service function not defined for non-interactive service action." >&2
            exit 1
        fi
    elif $add_route_flag; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Executing direct add_route action..."
        if [[ -z "$service_name_arg" || -z "$domain_arg" || -z "$backend_target_arg" ]]; then
            echo -e "${RED}ERROR: --add-route requires --service-name, --domain, and --backend-target." >&2
            exit 1
        fi
        if declare -F add_service_from_args > /dev/null; then
            add_service_from_args "$service_name_arg" "$domain_arg" "$backend_target_arg" "$backend_https_arg" "$skip_verify_arg"
            exit_code=$?
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] Add route action finished with exit code ${exit_code}."
            exit $exit_code
        else
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] CRITICAL ERROR: add_service_from_args function not defined." >&2
            exit 1
        fi
    elif $remove_route_flag; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Executing direct remove_route action..."
        if [[ -z "$filename_arg" ]]; then
            echo -e "${RED}ERROR: --remove-route requires --filename." >&2
            exit 1
        fi
        if declare -F remove_service_from_args > /dev/null; then
            remove_service_from_args "$filename_arg"
            exit_code=$?
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] Remove route action finished with exit code ${exit_code}."
            exit $exit_code
        else
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] CRITICAL ERROR: remove_service_from_args function not defined." >&2
            exit 1
        fi
    elif $show_cert_info_flag; then
        # echo "[$(date +'%Y-%m-%d %H:%M:%S')] Executing direct show_certificate_info action..." # Removed for cleaner output
        if declare -F show_certificate_info > /dev/null; then
            show_certificate_info # Call directly
            exit $?
        else
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] CRITICAL ERROR: show_certificate_info function not defined." >&2
            exit 1
        fi
    elif $view_log_flag; then
        if [[ -z "$log_type_arg" ]]; then # Should have been caught by parser, but double check
            echo -e "${RED}ERROR: --view-log requires a log_type argument (internal check).${NC}" >&2
            exit 1
        fi
        if declare -F get_log_lines > /dev/null; then
            # echo "[$(date +'%Y-%m-%d %H:%M:%S')] Executing direct get_log_lines action..." # Removed for cleaner output
            get_log_lines "$log_type_arg" "$lines_arg"
            exit $?
        else
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] CRITICAL ERROR: get_log_lines function not defined." >&2
            exit 1
        fi
    fi
fi

# Only show menu if not in non_interactive_mode already handled above
if ! $non_interactive_mode; then
    check_root
    check_dependencies # Check tools directly at the beginning

    while true; do
        print_header "Main Menu - Traefik Management"

        # Menu items - Renumbered after removing Git
        echo -e "| ${CYAN}1) Installation & Initial Setup    ${NC} |"
        echo -e "| ${CYAN}2) Configuration & Routes          ${NC} |"
        echo -e "| ${CYAN}3) Security & Certificates         ${NC} |"
        echo -e "| ${CYAN}4) Service & Logs                  ${NC} |"
        echo -e "| ${CYAN}5) Backup & Restore                ${NC} |"
        echo -e "| ${CYAN}6) Diagnostics & Info              ${NC} |"
        echo -e "| ${CYAN}7) Automation                      ${NC} |"
        echo -e "| ${CYAN}8) Maintenance & Updates           ${NC} |"
        echo "|-----------------------------------------|"
        echo -e "|   ${BOLD}9)${NC} Uninstall Traefik ${RED}(RISK!)      ${NC} |" # Uninstall moved to top level
        echo "|-----------------------------------------|"
        echo -e "|   ${BOLD}0)${NC} Exit Script                     ${NC} |"
        echo "+-----------------------------------------+";
        read -p "Your choice [0-9]: " main_choice # Range adjusted

        local sub_choice=-1 # Reset sub_choice

        case "$main_choice" in # Quote main_choice
            1) # --- Install / Update Submenu ---
                clear; print_header "Installation & Initial Setup";
                echo -e "|   ${BOLD}1)${NC} Install / Overwrite Traefik        |";
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}0)${NC} Back                               |";
                echo "+-----------------------------------------+";
                read -p "Choice [0-1]: " sub_choice
                case "$sub_choice" in 1) install_traefik ;; 0) ;; *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;;
            2) # --- Config & Routes Submenu ---
                clear; print_header "Configuration & Routes";
                echo -e "|   ${BOLD}1)${NC} Add New Service / Route            |";
                echo -e "|   ${BOLD}2)${NC} Modify Service / Route             |";
                echo -e "|   ${BOLD}3)${NC} Remove Service / Route             |";
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}4)${NC} Check Static Config (Hint V3)      |";
                echo -e "|   ${BOLD}5)${NC} Edit Static Config (...)           |";
                echo -e "|      ${YELLOW}(${STATIC_CONFIG_FILE})${NC}      |";
                echo -e "|   ${BOLD}6)${NC} Edit Middleware Config (...)       |";
                echo -e "|      ${YELLOW}(${MIDDLEWARES_FILE})${NC}      |";
                echo -e "|   ${BOLD}7)${NC} Edit EntryPoints (...)             |";
                echo -e "|      ${YELLOW}(${STATIC_CONFIG_FILE})${NC}      |";
                echo -e "|   ${BOLD}8)${NC} Edit Global TLS Opts (...)         |";
                echo -e "|      ${YELLOW}(${MIDDLEWARES_FILE})${NC}      |";
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}0)${NC} Back                               |";
                echo "+-----------------------------------------+";
                read -p "Choice [0-8]: " sub_choice
                case "$sub_choice" in 1) add_service ;; 2) modify_service ;; 3) remove_service ;; 4) check_static_config ;; 5) edit_static_config ;; 6) edit_middlewares_config ;; 7) edit_entrypoints ;; 8) edit_tls_options ;; 0) ;; *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;;
            3) # --- Security & Certificates Submenu ---
                clear; print_header "Security & Certificates";
                echo -e "|   ${BOLD}1)${NC} Manage Dashboard Users             |";
                echo -e "|   ${BOLD}2)${NC} Show Certificate Details (ACME)    |";
                echo -e "|   ${BOLD}3)${NC} Check Cert Expiry (< 14 Days)    |";
                echo -e "|   ${BOLD}4)${NC} Check for Insecure API             |";
                echo -e "|   ${BOLD}5)${NC} Show Example Fail2Ban Config       |";
                echo -e "|   ${BOLD}6)${NC} Add Plugin (Experimental)          |";
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}0)${NC} Back                               |";
                echo "+-----------------------------------------+";
                read -p "Choice [0-6]: " sub_choice
                case "$sub_choice" in 1) manage_dashboard_users ;; 2) show_certificate_info ;; 3) check_certificate_expiry ;; 4) check_insecure_api ;; 5) generate_fail2ban_config ;; 6) install_plugin ;; 0) ;; *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;;
            4) # --- Service & Logs Submenu ---
                clear; print_header "Service & Logs";
                echo -e "|   ${BOLD}1)${NC} START Traefik Service              |";
                echo -e "|   ${BOLD}2)${NC} STOP Traefik Service               |";
                echo -e "|   ${BOLD}3)${NC} RESTART Traefik Service            |";
                echo -e "|   ${BOLD}4)${NC} Show Traefik Service STATUS        |";
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}5)${NC} View Traefik Log (traefik.log)     |";
                echo -e "|   ${BOLD}6)${NC} View Access Log (access.log)       |";
                echo -e "|   ${BOLD}7)${NC} View Systemd Journal Log (traefik) |";
                echo -e "|   ${BOLD}8)${NC} View IP Access Log (...)           |";
                echo -e "|      ${YELLOW}(${IP_LOG_FILE})${NC}      |";
                echo -e "|   ${BOLD}9)${NC} View Autobackup Log (File)         |";
                echo -e "|  ${BOLD}10)${NC} View Autobackup Log (Journal)      |";
                echo -e "|  ${BOLD}11)${NC} View IP Logger Service Log (Jrnl)  |";
                # Auto-Pull Log removed
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}0)${NC} Back                               |";
                echo "+-----------------------------------------+";
                read -p "Choice [0-11]: " sub_choice # Range adjusted
                case "$sub_choice" in # Quote sub_choice
                     1) manage_service "start" ;; 2) manage_service "stop" ;; 3) manage_service "restart" ;; 4) manage_service "status" ;;
                     5) view_logs "traefik" ;; 6) view_logs "access" ;; 7) view_logs "journal" ;; 8) view_logs "ip_access" ;;
                     9) view_logs "autobackup_file" ;; 10) view_logs "autobackup" ;; 11) view_logs "ip_logger" ;;
                     # 12 removed
                     0) ;; *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;;
            5) # --- Backup & Restore Submenu ---
                 clear; print_header "Backup & Restore";
                 echo -e "|   ${BOLD}1)${NC} Create Configuration Backup        |";
                 echo -e "|   ${BOLD}2)${NC} Restore Backup ${YELLOW}(CAUTION!)${NC}       |";
                 echo "|-----------------------------------------|";
                 echo -e "|   ${BOLD}0)${NC} Back                               |";
                 echo "+-----------------------------------------+";
                 read -p "Choice [0-2]: " sub_choice
                 case "$sub_choice" in 1) backup_traefik false ;; 2) restore_traefik ;; 0) ;; *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;; # Explicitly pass false
            6) # --- Diagnostics & Info Submenu ---
                clear; print_header "Diagnostics & Info";
                echo -e "|   ${BOLD}1)${NC} Show Installed Traefik Version     |";
                echo -e "|   ${BOLD}2)${NC} Check Listening Ports (ss)         |";
                echo -e "|   ${BOLD}3)${NC} Test Backend Connectivity          |";
                echo -e "|   ${BOLD}4)${NC} Show Active Config (API/jq)        |";
                echo -e "|   ${BOLD}5)${NC} Perform Health Check               |";
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}0)${NC} Back                               |";
                echo "+-----------------------------------------+";
                read -p "Choice [0-5]: " sub_choice
                case "$sub_choice" in 1) show_traefik_version ;; 2) check_listening_ports ;; 3) test_backend_connectivity ;; 4) show_active_config ;; 5) health_check ;; 0) ;; *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;;
            7) # --- Automation Submenu ---
                clear; print_header "Automation";
                echo -e "|   ${BOLD}1)${NC} Setup/Modify Auto Backup ${GREEN}(Impl)${NC}   |";
                echo -e "|   ${BOLD}2)${NC} Remove Automatic Backup ${GREEN}(Impl)${NC}    |";
                echo -e "|   ${BOLD}3)${NC} Setup Dedicated IP Logging ${GREEN}(Impl)${NC} |";
                echo -e "|   ${BOLD}4)${NC} Remove Dedicated IP Log ${GREEN}(Impl)${NC}  |";
                # Auto-Pull removed
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}0)${NC} Back                               |";
                echo "+-----------------------------------------+";
                read -p "Choice [0-4]: " sub_choice # Range adjusted
                case "$sub_choice" in # Quote sub_choice
                    1) setup_autobackup ;;
                    2) remove_autobackup ;;
                    3) setup_ip_logging ;;
                    4) remove_ip_logging ;;
                    # 5, 6 removed
                    0) ;;
                    *) echo -e "${RED}Invalid choice.${NC}" >&2 ;;
                esac ;;
            8) # --- Maintenance & Updates Submenu ---
                 clear; print_header "Maintenance & Updates";
                 echo -e "|   ${BOLD}1)${NC} Check for New Traefik Version      |";
                 echo -e "|   ${BOLD}2)${NC} Update Traefik Binary ${YELLOW}(RISK!)${NC}   |";
                 echo -e "|   ${BOLD}3)${NC} Check Cert Expiry (< 14 Days)    |";
                 echo "|-----------------------------------------|";
                 echo -e "|   ${BOLD}0)${NC} Back                               |";
                 echo "+-----------------------------------------+";
                 read -p "Choice [0-3]: " sub_choice
                 case "$sub_choice" in # Quote sub_choice
                    1) check_traefik_updates ;;
                    2) update_traefik_binary ;;
                    3) check_certificate_expiry ;;
                    0) ;;
                    *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;;
            9) # --- Uninstall ---
                 uninstall_traefik ;; # This function has its own prompts, no submenu needed.
            0) # --- Exit Script ---
                echo "Exiting script. Goodbye!"; exit 0 ;;
            *) # --- Invalid Main Menu Choice ---
                echo ""; echo -e "${RED}ERROR: Invalid choice '$main_choice'.${NC}" >&2 ;;
        esac

        # Pause before showing main menu again unless exiting or returning from submenu (choice 0)
        if [[ "$main_choice" != "0" ]]; then
            # Only pause if an action was selected in the submenu (sub_choice is not 0 and not -1 which means it was used)
            # or if the main choice itself was invalid.
            # An invalid main_choice would result in sub_choice remaining -1.
            # A direct action from main menu (like 9) also means sub_choice is -1.
            if [[ "$sub_choice" -gt 0 ]] || ( [[ "$sub_choice" -eq -1 ]] && ! [[ "$main_choice" =~ ^[0-8]$ ]] ); then
                 # Don't pause if the submenu choice was 0 (Back) or if it was a direct main menu action (like 9)
                 # The second part of the OR condition:
                 # sub_choice is -1 (meaning no submenu was entered or submenu choice was 0 and then reset)
                 # AND main_choice was NOT one that leads to a submenu (0-8 leads to submenus or exit)
                 # This covers invalid main_choice.
                 # Main choices 1-8 lead to submenus. Main choice 9 is direct. Main choice 0 is direct.
                 # So, if sub_choice is > 0, it means a submenu action was taken.
                 # If sub_choice is -1, it means either a direct main menu action (like 9) or invalid main menu choice.
                 # We want to pause for invalid main menu choice.
                 # We also want to pause if a submenu action (sub_choice > 0) was taken.
                 # We do NOT want to pause if sub_choice was 0 (Back from submenu).
                 # We do NOT want to pause for direct main menu action 9.
                 if [[ "$sub_choice" -ne 0 ]] && [[ "$main_choice" -ne 9 ]]; then
                     echo ""; read -p "... Press Enter for main menu ..." dummy_var;
                 fi
            fi
        fi
    done
fi # End of interactive mode

exit 0
