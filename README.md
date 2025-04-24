# Traefik Management Script v2.0.0

A comprehensive Bash script for managing a Traefik v3 reverse proxy instance on Debian 12 systems.

This script provides a menu-driven interface to handle installation, configuration, service management, logging, backups, automated tasks, diagnostics, and updates for Traefik.

**Based on:** Original German script by fbnlrz, which was based on a guide by phoenyx. This version includes English translation, bug fixes, and implementation of automation features.

## Features

The script offers a wide range of functionalities organized into menus:

*   **Installation & Initial Setup:**
    *   Install a specific Traefik version.
    *   Guides through initial setup (Email, Domain, User/Pass).
    *   Creates necessary directories and base configuration files (`traefik.yaml`, `middlewares.yml`, dashboard config).
    *   Sets up and enables the `traefik.service` systemd unit with security hardening.
*   **Configuration & Routes:**
    *   Add new dynamic configuration files for services/routes (prompts for details).
    *   Modify existing dynamic configuration files using your default editor.
    *   Remove dynamic configuration files.
    *   Check static configuration syntax (using `yamllint` if installed).
    *   Edit the main static configuration (`traefik.yaml`).
    *   Edit the main middleware configuration (`middlewares.yml`).
    *   Edit EntryPoints (opens `traefik.yaml`).
    *   Edit Global TLS Options (opens `middlewares.yml`).
*   **Security & Certificates:**
    *   Manage dashboard users (add, remove, change password, list) using `htpasswd`.
    *   Show details of certificates stored in `acme.json` (requires `jq`, `openssl`).
    *   Check for certificates expiring within a specified threshold (default 14 days).
    *   Check if the Traefik API is configured insecurely (`api.insecure: true`).
    *   Display an example Fail2Ban configuration for Traefik dashboard authentication.
    *   Add experimental Traefik plugin declarations to `traefik.yaml`.
*   **Service & Logs:**
    *   Start, Stop, Restart, and check the Status of the `traefik.service`.
    *   View (tail -f) various log files:
        *   `traefik.log`
        *   `access.log`
        *   Systemd Journal for `traefik.service`
        *   Dedicated IP Access Log (`ip_access.log`, if enabled)
        *   Autobackup Log File (`traefik_autobackup.log`, if enabled)
        *   Autobackup Service Journal
        *   IP Logger Service Journal
*   **Backup & Restore:**
    *   Create timestamped `.tar.gz` backups of the entire Traefik configuration directory (`/opt/traefik`).
    *   Restore configuration from a chosen backup file (stops Traefik during restore).
*   **Diagnostics & Info:**
    *   Show the currently installed Traefik binary version.
    *   Check if Traefik is listening on ports 80 and 443 (using `ss`).
    *   Test connectivity to a backend URL (using `curl`).
    *   Show the active configuration reported by the Traefik API (requires `jq` and API access).
    *   Perform a health check (service status, ports, static config syntax, insecure API, dashboard reachability).
*   **Automation:**
    *   Setup/Modify automatic daily backups using systemd timer/service units.
    *   Remove automatic backup systemd units.
    *   Setup dedicated IP address logging (extracts IPs from JSON access log to a separate file using a helper script, systemd timer/service, and logrotate). Requires `jq`.
    *   Remove dedicated IP logging components.
*   **Maintenance & Updates:**
    *   Check GitHub for the latest Traefik release version.
    *   Update the Traefik binary to the latest or a specified version (stops/starts Traefik).
*   **Uninstall Traefik:**
    *   Completely removes the Traefik binary, configuration directory, log directory, systemd service files, and automation components created by this script. **Use with extreme caution!**

## Prerequisites

*   **Operating System:** Debian 12 (tested), likely compatible with other recent systemd-based Linux distributions (Ubuntu, etc.).
*   **Shell:** Bash.
*   **Privileges:** `sudo` access is required to run the script and manage system files/services.
*   **Core Utilities:** Standard Linux commands like `sed`, `awk`, `grep`, `curl`, `tar`, `find`, `ss`, `date`, `openssl`, `mkdir`, `chmod`, `chown`, `mv`, `rm`, `systemctl`, `realpath`.
*   **Required Dependencies (Installed by script if needed):**
    *   `apache2-utils` (for `htpasswd`): Needed for Dashboard User Management.
    *   `jq`: Needed for Certificate Details, Active Config display, IP Logging, Update Check, Update Binary.
*   **Optional Dependencies:**
    *   `yamllint`: Used for basic YAML syntax checking in the "Check Static Config" option. Install via `sudo apt install yamllint`.

## Installation / Setup

1.  **Download the Script:**
    Save the script content to a file on your server, for example, `traefik-manager.sh`. You can use `curl` or `wget`:


# Example using curl # curl -o traefikmanager.sh https://raw.githubusercontent.com/fbnlrz/traefikmanager/refs/heads/main/traefikmanager.sh

# Or, copy and paste the script content into a file using nano:
nano traefik-manager.sh
# (Paste the script content, then Ctrl+X, then Y, then Enter to save)
2.  **Make it Executable:**


bash chmod +x traefik-manager.sh

## Usage

### Interactive Mode

Run the script with `sudo` and `bash`:


bash sudo bash traefik-manager.sh

You will be presented with the main menu. Enter the number corresponding to the desired category and press Enter. Submenus will guide you through specific actions.

*   Follow the on-screen prompts.
*   Confirmations (`yes`/`no`) are required for potentially destructive actions.

### Non-Interactive Mode (Backup Only)

The script supports a single non-interactive mode specifically for creating backups, intended for use with cron or the script's own systemd-based automation.


bash sudo /path/to/traefik-manager.sh --run-backup

*   Replace `/path/to/traefik-manager.sh` with the actual path to the script.
*   This command will execute the `backup_traefik` function directly.
*   Output (success or failure messages) will be printed to standard output/error. If using the script's automation setup (Menu 7 -> 1), this output is appended to `/var/log/traefik_autobackup.log`.

## Configuration

*   **Script Variables:** Key paths and default settings are defined as variables at the top of the script (e.g., `TRAEFIK_CONFIG_DIR`, `TRAEFIK_LOG_DIR`, `BACKUP_DIR`, `DEFAULT_TRAEFIK_VERSION`). You can modify these defaults *before* running the script for the first time if needed, but ensure the paths are valid and writable.
*   **Traefik Configuration:** The script creates and manages Traefik's configuration files within `/opt/traefik` by default.
    *   **Static Config:** `/opt/traefik/config/traefik.yaml`
    *   **Dynamic Config Directory:** `/opt/traefik/dynamic_conf/`
    *   **Certificates:** `/opt/traefik/certs/` (including `acme.json`)
    *   **Auth File:** `/opt/traefik/traefik_auth`
*   **IMPORTANT (`trustedIPs`):** After the initial installation (Menu 1 -> 1), you **must** review and edit the `forwardedHeaders.trustedIPs` list within the static configuration file (`/opt/traefik/config/traefik.yaml`) to include the IP address(es) of any upstream proxies or your local router if Traefik is not directly exposed to the internet. Failure to do so might prevent Traefik from correctly identifying the original client IP address.

## Important Notes & Warnings

*   **Root Privileges:** The script requires `sudo` to manage system services, install packages, and write to system directories (`/etc`, `/opt`, `/var/log`, `/usr/local/bin`).
*   **Destructive Actions:** Operations like **Uninstall Traefik** (Menu 9) and **Restore Backup** (Menu 5 -> 2) are irreversible and will delete data. Use with extreme caution and ensure you have backups.
*   **Backups:** Regularly use the backup feature (Menu 5 -> 1) or set up automatic backups (Menu 7 -> 1). Store backups securely, potentially off-server.
*   **Experimental Features:** Plugin management is marked as experimental. Use with care.
*   **Automation:** Setting up Autobackup or IP Logging creates systemd `.service` and `.timer` files, a helper script (`/usr/local/sbin/`), and a logrotate configuration (`/etc/logrotate.d/`). Removing these features via the script aims to clean up these components.
*   **JSON Logs:** The dedicated IP Logging feature and the Fail2Ban example rely on Traefik's access log being configured in `json` format in `traefik.yaml`.
*   **Editing Files:** When editing configuration files via the script, your default command-line editor (`$EDITOR`, defaulting to `nano`) will be used with `sudo`. Ensure you save your changes correctly.

## Basic Troubleshooting

*   **Script Errors:** Check the script's output for any `ERROR:` messages.
*   **Traefik Not Starting:**
    *   Check status: `sudo systemctl status traefik.service`
    *   Check journal logs: `sudo journalctl -u traefik.service -e --no-pager -l` (Look for errors, especially near the end).
    *   Validate YAML: Manually review `traefik.yaml` and dynamic config files for syntax errors. Use `yamllint` if installed.
*   **Automation Not Running:**
    *   Check timer status: `sudo systemctl status traefik-autobackup.timer` or `sudo systemctl status traefik-ip-logger.timer`
    *   List timers: `sudo systemctl list-timers | grep traefik`
    *   Check service journal: `sudo journalctl -u traefik-autobackup.service` or `sudo journalctl -u traefik-ip-logger.service`
    *   Check file logs: `/var/log/traefik_autobackup.log` or `/var/log/traefik/ip_access.log`

## License
