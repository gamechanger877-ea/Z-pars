#!/bin/bash
# Z-pars VPN Panel Installer
# Usage: curl -sL https://raw.githubusercontent.com/yourusername/Z-pars/main/install.sh | bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║     _____            ____                           ║
║    |__  /_ __ ___   |  _ \ __ _ _ __  ___ _ __      ║
║      / /| '__/ _ \  | |_) / _` | '_ \/ __| '_ \     ║
║     / /_| | | (_) | |  __/ (_| | |_) \__ \ |_) |    ║
║    /____|_|  \___/  |_|   \__,_| .__/|___/ .__/     ║
║                                |_|       |_|        ║
║                 VPN Panel v4.0                      ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
}

# Install dependencies
install_deps() {
    echo -e "${BLUE}[*] Installing dependencies...${NC}"
    
    if [ -f /etc/debian_version ]; then
        apt-get update -qq
        apt-get install -y -qq curl wget git unzip jq qrencode sqlite3 \
            python3 python3-pip nginx certbot uuid-runtime bc
    elif [ -f /etc/redhat-release ]; then
        yum install -y -q epel-release
        yum install -y -q curl wget git unzip jq qrencode sqlite3 \
            python3 python3-pip nginx certbot util-linux bc
    else
        echo -e "${RED}Unsupported OS${NC}"
        exit 1
    fi
}

# Install Xray
install_xray() {
    echo -e "${BLUE}[*] Installing Xray...${NC}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # Create directories
    mkdir -p /etc/Z-pars /var/log/Z-pars /var/www/Z-pars /opt/Z-pars/{users,database,backups}
    
    # Generate UUID for panel
    PANEL_UUID=$(uuidgen)
    echo $PANEL_UUID > /etc/Z-pars/panel_uuid
}

# Create main script
create_zpars_script() {
    echo -e "${BLUE}[*] Creating Z-pars command...${NC}"
    
    cat > /usr/local/bin/Z-pars << 'EOF'
#!/bin/bash
# Z-pars VPN Panel Main Command

PANEL_DIR="/opt/Z-pars"
DB_FILE="$PANEL_DIR/database/users.db"
CONFIG_DIR="/etc/xray"
USERS_DIR="$PANEL_DIR/users"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Functions
show_banner() {
    echo -e "${CYAN}"
    echo "┌─────────────────────────────────────────────────────┐"
    echo "│                   Z-pars VPN Panel                  │"
    echo "└─────────────────────────────────────────────────────┘"
    echo -e "${NC}"
}

show_help() {
    echo -e "${CYAN}Usage:${NC}"
    echo "  Z-pars [command] [options]"
    echo ""
    echo "${CYAN}Commands:${NC}"
    echo "  start           - Start VPN panel"
    echo "  stop            - Stop VPN panel"
    echo "  restart         - Restart VPN panel"
    echo "  status          - Show panel status"
    echo ""
    echo "  add-user <name> - Add new VPN user"
    echo "  list-users      - List all users"
    echo "  delete-user <name> - Delete user"
    echo "  user-config <name> - Show user config"
    echo "  reset-traffic <name> - Reset user traffic"
    echo ""
    echo "  web             - Start web interface"
    echo "  api             - Show API information"
    echo "  backup          - Backup database"
    echo "  restore         - Restore from backup"
    echo ""
    echo "  update          - Update Z-pars"
    echo "  uninstall       - Remove Z-pars"
    echo "  help            - Show this help"
}

# Initialize database
init_db() {
    if [ ! -f "$DB_FILE" ]; then
        sqlite3 "$DB_FILE" "CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            uuid TEXT UNIQUE NOT NULL,
            email TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expire_date DATETIME,
            data_limit BIGINT DEFAULT 107374182400,
            used_data BIGINT DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            is_admin INTEGER DEFAULT 0
        );"
        
        # Create admin user
        ADMIN_UUID=$(uuidgen)
        ADMIN_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 8)
        HASHED_PASS=$(echo -n "$ADMIN_PASS" | sha256sum | cut -d' ' -f1)
        
        sqlite3 "$DB_FILE" "INSERT INTO users (username, password, uuid, is_admin) 
                          VALUES ('admin', '$HASHED_PASS', '$ADMIN_UUID', 1);"
        
        echo "Admin created: admin / $ADMIN_PASS" > "$PANEL_DIR/admin_credentials.txt"
    fi
}

# Start panel
start_panel() {
    if [ ! -f "/etc/systemd/system/Z-pars.service" ]; then
        create_service
    fi
    
    systemctl start Z-pars
    systemctl start nginx
    echo -e "${GREEN}[+] Panel started${NC}"
}

# Stop panel
stop_panel() {
    systemctl stop Z-pars
    echo -e "${YELLOW}[-] Panel stopped${NC}"
}

# Create systemd service
create_service() {
    cat > /etc/systemd/system/Z-pars.service << SERVICE_EOF
[Unit]
Description=Z-pars VPN Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/Z-pars
ExecStart=/usr/bin/python3 /opt/Z-pars/panel_api.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    systemctl daemon-reload
    systemctl enable Z-pars
}

# Add user
add_user() {
    if [ -z "$1" ]; then
        echo -e "${RED}Error: Username required${NC}"
        echo "Usage: Z-pars add-user <username>"
        return 1
    fi
    
    username="$1"
    
    # Check if user exists
    existing=$(sqlite3 "$DB_FILE" "SELECT username FROM users WHERE username='$username'")
    if [ -n "$existing" ]; then
        echo -e "${RED}Error: User '$username' already exists${NC}"
        return 1
    fi
    
    # Generate credentials
    password=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 8)
    uuid=$(uuidgen)
    hashed_pass=$(echo -n "$password" | sha256sum | cut -d' ' -f1)
    
    # Add to database
    sqlite3 "$DB_FILE" "INSERT INTO users (username, password, uuid) 
                       VALUES ('$username', '$hashed_pass', '$uuid');"
    
    # Create user config
    create_user_config "$username" "$uuid"
    
    # Update Xray config
    update_xray_config
    
    echo -e "${GREEN}[+] User '$username' created${NC}"
    echo "Username: $username"
    echo "Password: $password"
    echo "UUID: $uuid"
    
    # Generate QR code
    SERVER_IP=$(curl -4 -s icanhazip.com)
    config_url="vless://$uuid@$SERVER_IP:443?type=tcp&security=reality&sni=www.google.com&fp=chrome#$username"
    echo -e "\n${CYAN}Config URL:${NC}"
    echo "$config_url"
    echo -e "\n${CYAN}QR Code:${NC}"
    echo "$config_url" | qrencode -t UTF8
}

# Create user config
create_user_config() {
    username="$1"
    uuid="$2"
    SERVER_IP=$(curl -4 -s icanhazip.com)
    
    cat > "$USERS_DIR/$username.conf" << CONFIG_EOF
# Z-pars VPN Configuration
# User: $username
# Generated: $(date)

=== Server Information ===
Server IP: $SERVER_IP
Server Port: 443
Protocol: VLESS + Reality
Transport: TCP
SNI: www.google.com
Flow: xtls-rprx-vision

=== Connection Details ===
UUID: $uuid

=== VLESS Config ===
vless://$uuid@$SERVER_IP:443?type=tcp&security=reality&sni=www.google.com&fp=chrome#$username

=== Subscription Link ===
vless://$uuid@$SERVER_IP:443?type=tcp&security=reality&sni=www.google.com&fp=chrome#$username

=== QR Code (Scan with client) ===
Save QR code from: $USERS_DIR/$username.png
CONFIG_EOF
    
    # Generate QR code image
    echo "vless://$uuid@$SERVER_IP:443?type=tcp&security=reality&sni=www.google.com&fp=chrome#$username" | \
        qrencode -o "$USERS_DIR/$username.png" -s 10
}

# Update Xray config
update_xray_config() {
    # Get all UUIDs
    uuids=$(sqlite3 "$DB_FILE" "SELECT uuid FROM users WHERE enabled=1" | tr '\n' ' ')
    
    # Create new config
    cat > "$CONFIG_DIR/config.json" << XRAY_EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
EOF
    
    # Add clients
    first=true
    for uuid in $uuids; do
        if [ "$first" = true ]; then
            first=false
        else
            echo "          ," >> "$CONFIG_DIR/config.json"
        fi
        cat >> "$CONFIG_DIR/config.json" << EOF
          {
            "id": "$uuid",
            "flow": "xtls-rprx-vision"
          }
EOF
    done
    
    cat >> "$CONFIG_DIR/config.json" << XRAY_EOF
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "www.google.com:443",
          "serverNames": ["www.google.com", "www.cloudflare.com"],
          "privateKey": "$(xray x25519 | grep 'Private key:' | cut -d':' -f2 | tr -d ' ')",
          "shortId": "$(openssl rand -hex 8)",
          "minClientVer": "",
          "maxClientVer": "",
          "maxTimeDiff": 0,
          "fingerprint": "chrome"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
XRAY_EOF
    
    # Restart Xray
    systemctl restart xray
}

# List users
list_users() {
    echo -e "${CYAN}VPN Users List:${NC}"
    echo "┌────────────┬────────────────────┬────────────┬──────────┐"
    echo "│ Username   │ UUID               │ Used       │ Status   │"
    echo "├────────────┼────────────────────┼────────────┼──────────┤"
    
    sqlite3 "$DB_FILE" "SELECT username, uuid, 
                       printf('%.1f', used_data/1073741824.0) as used_gb,
                       CASE WHEN enabled=1 THEN '✅' ELSE '❌' END as status
                       FROM users" | while IFS='|' read -r username uuid used status; do
        printf "│ %-10s │ %-18s │ %-10s │ %-8s │\n" \
               "$username" "${uuid:0:8}..." "$used GB" "$status"
    done
    
    echo "└────────────┴────────────────────┴────────────┴──────────┘"
}

# Show user config
user_config() {
    if [ -z "$1" ]; then
        echo -e "${RED}Error: Username required${NC}"
        return 1
    fi
    
    username="$1"
    
    if [ ! -f "$USERS_DIR/$username.conf" ]; then
        echo -e "${RED}Error: User '$username' not found${NC}"
        return 1
    fi
    
    cat "$USERS_DIR/$username.conf"
}

# Delete user
delete_user() {
    if [ -z "$1" ]; then
        echo -e "${RED}Error: Username required${NC}"
        return 1
    fi
    
    username="$1"
    
    # Check if user exists
    existing=$(sqlite3 "$DB_FILE" "SELECT username FROM users WHERE username='$username'")
    if [ -z "$existing" ]; then
        echo -e "${RED}Error: User '$username' not found${NC}"
        return 1
    fi
    
    # Delete from database
    sqlite3 "$DB_FILE" "DELETE FROM users WHERE username='$username'"
    
    # Remove config files
    rm -f "$USERS_DIR/$username.conf" "$USERS_DIR/$username.png"
    
    # Update Xray config
    update_xray_config
    
    echo -e "${GREEN}[+] User '$username' deleted${NC}"
}

# Start web interface
start_web() {
    # Create web interface
    mkdir -p /var/www/Z-pars
    
    cat > /var/www/Z-pars/index.html << WEB_EOF
<!DOCTYPE html>
<html>
<head>
    <title>Z-pars VPN Panel</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a1a; color: white; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .header { background: #667eea; padding: 20px; border-radius: 10px; }
        .card { background: #2d2d2d; padding: 20px; margin: 10px 0; border-radius: 5px; }
        button { background: #667eea; color: white; border: none; padding: 10px; border-radius: 5px; }
        pre { background: #000; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Z-pars VPN Panel</h1>
            <p>Manage your VPN users and configurations</p>
        </div>
        
        <div class="card">
            <h3>Quick Actions</h3>
            <button onclick="addUser()">Add User</button>
            <button onclick="listUsers()">List Users</button>
        </div>
        
        <div class="card">
            <h3>Server Status</h3>
            <div id="status">Loading...</div>
        </div>
        
        <div class="card">
            <h3>Users List</h3>
            <div id="users"></div>
        </div>
    </div>
    
    <script>
        async function getStatus() {
            const res = await fetch('/api/status');
            const data = await res.json();
            document.getElementById('status').innerHTML = 
                \`Xray: \${data.xray}<br>Users: \${data.users}\`;
        }
        
        async function listUsers() {
            const res = await fetch('/api/users');
            const users = await res.json();
            let html = '<table style="width:100%">';
            users.forEach(user => {
                html += \`<tr><td>\${user.username}</td><td>\${user.uuid}</td></tr>\`;
            });
            html += '</table>';
            document.getElementById('users').innerHTML = html;
        }
        
        function addUser() {
            const username = prompt('Enter username:');
            if (username) {
                fetch('/api/add-user', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username: username})
                }).then(res => res.json())
                .then(data => alert('User created: ' + data.uuid));
            }
        }
        
        // Load initial data
        getStatus();
        listUsers();
    </script>
</body>
</html>
WEB_EOF
    
    # Start nginx
    systemctl start nginx
    
    SERVER_IP=$(curl -4 -s icanhazip.com)
    echo -e "${GREEN}[+] Web interface started${NC}"
    echo -e "Access at: ${YELLOW}http://$SERVER_IP${NC}"
}

# Create API server
create_api() {
    cat > /opt/Z-pars/panel_api.py << PYTHON_EOF
#!/usr/bin/env python3
import sqlite3, json, os, subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

DB_FILE = '/opt/Z-pars/database/users.db'

class ZParsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/status':
            self.send_json(self.get_status())
        elif self.path == '/api/users':
            self.send_json(self.get_users())
        else:
            self.send_error(404)
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length).decode()
        data = json.loads(body)
        
        if self.path == '/api/add-user':
            response = self.add_user(data)
            self.send_json(response)
        else:
            self.send_error(404)
    
    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def get_status(self):
        # Check Xray status
        xray_status = subprocess.run(['systemctl', 'is-active', 'xray'], 
                                     capture_output=True).stdout.decode().strip()
        
        # Count users
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        user_count = cursor.fetchone()[0]
        conn.close()
        
        return {'xray': xray_status, 'users': user_count}
    
    def get_users(self):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT username, uuid FROM users')
        users = [{'username': row[0], 'uuid': row[1]} for row in cursor.fetchall()]
        conn.close()
        return users
    
    def add_user(self, data):
        import uuid as uuid_lib, hashlib, secrets
        
        username = data.get('username')
        user_uuid = str(uuid_lib.uuid4())
        password = secrets.token_urlsafe(8)
        hashed_pass = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password, uuid) VALUES (?, ?, ?)',
                      (username, hashed_pass, user_uuid))
        conn.commit()
        conn.close()
        
        # Update Xray config
        subprocess.run(['Z-pars', 'update-config'], capture_output=True)
        
        return {'success': True, 'uuid': user_uuid, 'password': password}

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), ZParsHandler)
    print('Z-pars API running on port 8080...')
    server.serve_forever()
PYTHON_EOF
    
    chmod +x /opt/Z-pars/panel_api.py
}

# Main command handler
case "$1" in
    start)
        start_panel
        ;;
    stop)
        stop_panel
        ;;
    restart)
        stop_panel
        start_panel
        ;;
    status)
        systemctl status Z-pars
        systemctl status xray
        ;;
    add-user)
        init_db
        add_user "$2"
        ;;
    list-users)
        init_db
        list_users
        ;;
    "user-config")
        user_config "$2"
        ;;
    "delete-user")
        delete_user "$2"
        ;;
    "reset-traffic")
        echo "Feature coming soon"
        ;;
    web)
        start_web
        ;;
    api)
        create_api
        echo -e "${GREEN}API server created at /opt/Z-pars/panel_api.py${NC}"
        ;;
    backup)
        backup_file="/opt/Z-pars/backups/backup_$(date +%Y%m%d_%H%M%S).db"
        cp "$DB_FILE" "$backup_file"
        echo -e "${GREEN}Backup created: $backup_file${NC}"
        ;;
    restore)
        echo -e "${YELLOW}Feature coming soon${NC}"
        ;;
    update)
        echo -e "${BLUE}Updating Z-pars...${NC}"
        curl -sL https://raw.githubusercontent.com/yourusername/Z-pars/main/install.sh | bash
        ;;
    uninstall)
        echo -e "${RED}Are you sure? (y/n): ${NC}"
        read confirm
        if [ "$confirm" = "y" ]; then
            systemctl stop Z-pars
            systemctl disable Z-pars
            rm -f /etc/systemd/system/Z-pars.service
            rm -f /usr/local/bin/Z-pars
            rm -rf /opt/Z-pars
            echo -e "${GREEN}Z-pars uninstalled${NC}"
        fi
        ;;
    help|--help|-h)
        show_banner
        show_help
        ;;
    *)
        if [ -z "$1" ]; then
            show_banner
            show_help
        else
            echo -e "${RED}Unknown command: $1${NC}"
            echo "Use 'Z-pars help' for usage information"
        fi
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/Z-pars
}

# Create one-click install config
create_oneclick_config() {
    echo -e "${BLUE}[*] Creating one-click install configuration...${NC}"
    
    cat > /etc/xray/oneclick.json << ONECLICK_EOF
{
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "www.google.com:443",
          "serverNames": ["www.google.com", "www.cloudflare.com"],
          "privateKey": "",
          "shortId": "",
          "fingerprint": "chrome"
        }
      }
    }
  ]
}
ONECLICK_EOF
}

# Setup firewall
setup_firewall() {
    echo -e "${BLUE}[*] Configuring firewall...${NC}"
    
    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp
        ufw allow 443/tcp
        ufw allow 80/tcp
        ufw allow 8080/tcp
        ufw --force enable
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=8080/tcp
        firewall-cmd --reload
    fi
}

# Final setup
final_setup() {
    echo -e "${BLUE}[*] Finalizing installation...${NC}"
    
    # Create Z-pars command
    create_zpars_script
    
    # Initialize database
    /usr/local/bin/Z-pars api > /dev/null 2>&1
    
    # Create one-click config
    create_oneclick_config
    
    # Setup firewall
    setup_firewall
    
    # Start services
    systemctl start xray
    systemctl enable xray
    
    echo -e "${GREEN}[✓] Installation complete!${NC}"
}

# Show success message
show_success() {
    SERVER_IP=$(curl -4 -s icanhazip.com)
    
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║          Z-pars VPN Panel Installed!            ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${CYAN}Quick Start:${NC}"
    echo "────────────────────"
    echo -e "Add a user:       ${YELLOW}Z-pars add-user username${NC}"
    echo -e "List users:       ${YELLOW}Z-pars list-users${NC}"
    echo -e "Start web panel:  ${YELLOW}Z-pars web${NC}"
    echo -e "Check status:     ${YELLOW}Z-pars status${NC}"
    echo ""
    echo -e "${CYAN}Access Information:${NC}"
    echo "────────────────────"
    echo -e "Server IP:        ${YELLOW}$SERVER_IP${NC}"
    echo -e "VPN Port:         ${YELLOW}443${NC}"
    echo -e "Web Interface:    ${YELLOW}http://$SERVER_IP${NC}"
    echo ""
    echo -e "${CYAN}Admin Credentials:${NC}"
    echo "────────────────────"
    echo -e "Check: ${YELLOW}cat /opt/Z-pars/admin_credentials.txt${NC}"
    echo ""
    echo -e "${GREEN}Type 'Z-pars help' for all commands${NC}"
}

# Main installation
main() {
    show_banner
    check_root
    install_deps
    install_xray
    final_setup
    show_success
}

# Run installation
main
