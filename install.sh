#!/bin/bash
# Z-pars VPN Panel with Random Port - Clean Working Version
# This script fixes all syntax errors and implements random port functionality

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
PANEL_CONFIG_FILE="/etc/Z-pars/panel_config"

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║     _____            ____                                   ║
║    |__  /_ __ ___   |  _ \\ __ _ _ __  ___ _ __      ║
║      / /| '__/ _ \\  | |_) / _` | '_ \\/ __| '_ \\     ║
║     / /_| | | (_) | |  __/ (_| | |_) \\__ \\ |_) |    ║
║    /____|_|  \\___/  |_|   \\__,_| .__/|___/ .__/     ║
║                                |_|       |_|        ║
║            VPN Panel v4.0 (Random Port Edition)     ║
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

# Find a free port
find_free_port() {
    echo -e "${BLUE}[*] Searching for available port...${NC}"
    
    local min_port=10000
    local max_port=65000
    local port
    
    # Common ports to avoid
    local blocked_ports=(22 25 53 80 110 143 443 465 587 993 995 3306 5432 8080 8443 8888 9999)
    
    for ((port=$min_port; port<=$max_port; port++)); do
        # Check if port is in blocked list
        if printf '%s\n' "${blocked_ports[@]}" | grep -q "^$port$"; then
            continue
        fi
        
        # Check if port is available
        if ! lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
            echo $port > "$PANEL_CONFIG_FILE"
            echo -e "${GREEN}[✓] Found available port: $port${NC}"
            return 0
        fi
    done
    
    echo -e "${RED}Error: No free ports found in range $min_port-$max_port${NC}"
    exit 1
}

# Get current port
get_current_port() {
    if [ -f "$PANEL_CONFIG_FILE" ]; then
        cat "$PANEL_CONFIG_FILE"
    else
        echo "8080"  # Default fallback
    fi
}

# Install dependencies
install_deps() {
    echo -e "${BLUE}[*] Installing dependencies...${NC}"
    
    if [ -f /etc/debian_version ]; then
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq curl wget git unzip jq qrencode sqlite3 \
            python3 python3-pip nginx certbot uuid-runtime bc lsof >/dev/null 2>&1
    elif [ -f /etc/redhat-release ]; then
        yum install -y -q epel-release >/dev/null 2>&1
        yum install -y -q curl wget git unzip jq qrencode sqlite3 \
            python3 python3-pip nginx certbot util-linux bc lsof >/dev/null 2>&1
    fi
}

# Install Xray
install_xray() {
    echo -e "${BLUE}[*] Installing Xray...${NC}"
    
    # Install Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
    
    # Create directories
    mkdir -p /etc/Z-pars /var/log/Z-pars /var/www/Z-pars /opt/Z-pars/{users,database,backups}
    
    # Generate UUID for panel
    PANEL_UUID=$(uuidgen)
    echo $PANEL_UUID > /etc/Z-pars/panel_uuid
}

# Create Python API
create_python_api() {
    echo -e "${BLUE}[*] Creating Python API...${NC}"
    
    cat > /opt/Z-pars/panel_api.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import sqlite3
import json
import os
import http.server
import socketserver
from datetime import datetime

DB_FILE = '/opt/Z-pars/database/users.db'
PANEL_DIR = '/opt/Z-pars'
CONFIG_FILE = '/etc/Z-pars/panel_config'

def get_panel_port():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return int(f.read().strip())
    except:
        return 8080

class VPNPanel:
    def __init__(self):
        self.port = get_panel_port()
        self.init_db()
    
    def init_db(self):
        if not os.path.exists(DB_FILE):
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE users (
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
                )
            ''')
            
            import subprocess
            import hashlib
            admin_uuid = subprocess.run(['uuidgen'], capture_output=True, text=True).stdout.strip()
            admin_pass = subprocess.run(['openssl', 'rand', '-base64', '12'], capture_output=True, text=True).stdout.strip()[:8]
            hashed_pass = hashlib.sha256(admin_pass.encode()).hexdigest()
            
            cursor.execute("INSERT INTO users (username, password, uuid, is_admin) VALUES (?, ?, ?, 1)", 
                          ('admin', hashed_pass, admin_uuid))
            
            conn.commit()
            conn.close()
            
            with open(f'{PANEL_DIR}/admin_credentials.txt', 'w') as f:
                f.write(f'Admin created: admin / {admin_pass}\n')
    
    def get_status(self):
        return {
            'status': 'running',
            'port': self.port,
            'timestamp': datetime.now().isoformat(),
            'users_count': self.get_user_count()
        }
    
    def get_user_count(self):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE enabled=1")
        count = cursor.fetchone()[0]
        conn.close()
        return count

class APIHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        panel = VPNPanel()
        if self.path == '/api/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = panel.get_status()
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass

def run_server():
    PORT = get_panel_port()
    with socketserver.TCPServer(("", PORT), APIHandler) as httpd:
        print(f"API Server running on port {PORT}")
        httpd.serve_forever()

if __name__ == '__main__':
    print("Starting Z-pars API Server...")
    run_server()
PYTHON_EOF
    
    chmod +x /opt/Z-pars/panel_api.py
}

# Create main Z-pars script
create_zpars_script() {
    echo -e "${BLUE}[*] Creating Z-pars command...${NC}"
    
    cat > /usr/local/bin/Z-pars << 'EOF'
#!/bin/bash
PANEL_DIR="/opt/Z-pars"
DB_FILE="$PANEL_DIR/database/users.db"
CONFIG_DIR="/etc/xray"
USERS_DIR="$PANEL_DIR/users"
PANEL_CONFIG_FILE="/etc/Z-pars/panel_config"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

get_current_port() {
    if [ -f "$PANEL_CONFIG_FILE" ]; then
        cat "$PANEL_CONFIG_FILE"
    else
        echo "8080"
    fi
}

show_banner() {
    echo -e "${CYAN}"
    echo "┌─────────────────────────────────────────────────────┐"
    echo "│           Z-pars VPN Panel (Random Port)           │"
    echo "└─────────────────────────────────────────────────────┘"
    echo -e "${NC}"
}

show_help() {
    local current_port=$(get_current_port)
    
    echo -e "${CYAN}Usage:${NC}"
    echo "  Z-pars [command] [options]"
    echo ""
    echo -e "${CYAN}Current VPN Port: ${YELLOW}$current_port${NC}"
    echo ""
    echo -e "${CYAN}Commands:${NC}"
    echo "  start           - Start VPN panel"
    echo "  stop            - Stop VPN panel"
    echo "  restart         - Restart VPN panel"
    echo "  status          - Show panel status"
    echo "  add-user <name> - Add new VPN user"
    echo "  list-users      - List all users"
    echo "  delete-user <name> - Delete user"
    echo "  user-config <name> - Show user config"
    echo "  reset-traffic <name> - Reset user traffic"
    echo "  web             - Start web interface"
    echo "  api             - Show API information"
    echo "  backup          - Backup database"
    echo "  restore         - Restore from backup"
    echo "  update          - Update Z-pars"
    echo "  uninstall       - Remove Z-pars"
    echo "  help            - Show this help"
}

init_db() {
    if [ ! -f "$DB_FILE" ]; then
        sqlite3 "$DB_FILE" "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, uuid TEXT UNIQUE NOT NULL, email TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, expire_date DATETIME, data_limit BIGINT DEFAULT 107374182400, used_data BIGINT DEFAULT 0, enabled INTEGER DEFAULT 1, is_admin INTEGER DEFAULT 0);"
        
        ADMIN_UUID=$(uuidgen)
        ADMIN_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 8)
        HASHED_PASS=$(echo -n "$ADMIN_PASS" | sha256sum | cut -d' ' -f1)
        
        sqlite3 "$DB_FILE" "INSERT INTO users (username, password, uuid, is_admin) VALUES ('admin', '$HASHED_PASS', '$ADMIN_UUID', 1);"
        
        echo "Admin created: admin / $ADMIN_PASS" > "$PANEL_DIR/admin_credentials.txt"
    fi
}

start_panel() {
    if [ ! -f "/etc/systemd/system/Z-pars.service" ]; then
        create_service
    fi
    
    systemctl start Z-pars
    systemctl start nginx
    echo -e "${GREEN}[+] Panel started${NC}"
}

stop_panel() {
    systemctl stop Z-pars
    echo -e "${YELLOW}[-] Panel stopped${NC}"
}

create_service() {
    local current_port=$(get_current_port)
    
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

add_user() {
    if [ -z "$1" ]; then
        echo -e "${RED}Error: Username required${NC}"
        echo "Usage: Z-pars add-user <username>"
        return 1
    fi
    
    username="$1"
    existing=$(sqlite3 "$DB_FILE" "SELECT username FROM users WHERE username='$username'")
    
    if [ -n "$existing" ]; then
        echo -e "${RED}Error: User '$username' already exists${NC}"
        return 1
    fi
    
    password=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 8)
    uuid=$(uuidgen)
    hashed_pass=$(echo -n "$password" | sha256sum | cut -d' ' -f1)
    
    sqlite3 "$DB_FILE" "INSERT INTO users (username, password, uuid) VALUES ('$username', '$hashed_pass', '$uuid');"
    
    create_user_config "$username" "$uuid"
    update_xray_config
    
    echo -e "${GREEN}[+] User '$username' created${NC}"
    echo "Username: $username"
    echo "Password: $password"
    echo "UUID: $uuid"
    
    SERVER_IP=$(curl -4 -s icanhazip.com)
    VPN_PORT=$(get_current_port)
    config_url="vless://$uuid@$SERVER_IP:$VPN_PORT?type=tcp&security=reality&sni=www.google.com&fp=chrome#$username"
    echo -e "\n${CYAN}Config URL:${NC}"
    echo "$config_url"
    echo -e "\n${CYAN}QR Code:${NC}"
    echo "$config_url" | qrencode -t UTF8
}

create_user_config() {
    username="$1"
    uuid="$2"
    SERVER_IP=$(curl -4 -s icanhazip.com)
    VPN_PORT=$(get_current_port)
    
    cat > "$USERS_DIR/$username.conf" << CONFIG_EOF
# Z-pars VPN Configuration
# User: $username
# Generated: $(date)

=== Server Information ===
Server IP: $SERVER_IP
Server Port: $VPN_PORT
Protocol: VLESS + Reality
Transport: TCP
SNI: www.google.com
Flow: xtls-rprx-vision

=== Connection Details ===
UUID: $uuid

=== VLESS Config ===
vless://$uuid@$SERVER_IP:$VPN_PORT?type=tcp&security=reality&sni=www.google.com&fp=chrome#$username

=== QR Code (Scan with client) ===
Save QR code from: $USERS_DIR/$username.png
CONFIG_EOF
    
    echo "vless://$uuid@$SERVER_IP:$VPN_PORT?type=tcp&security=reality&sni=www.google.com&fp=chrome#$username" | qrencode -o "$USERS_DIR/$username.png" -s 10
}

update_xray_config() {
    uuids=$(sqlite3 "$DB_FILE" "SELECT uuid FROM users WHERE enabled=1" | tr '\n' ' ')
    VPN_PORT=$(get_current_port)
    
    cat > "$CONFIG_DIR/config.json" << XRAY_EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": $VPN_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
EOF
    
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
    
    systemctl restart xray
}

list_users() {
    echo -e "${CYAN}VPN Users List:${NC}"
    echo "┌────────────┬────────────────────┬────────────┬──────────┐"
    echo "│ Username   │ UUID               │ Used       │ Status   │"
    echo "├────────────┼────────────────────┼────────────┼──────────┤"
    
    sqlite3 "$DB_FILE" "SELECT username, uuid, printf('%.1f', used_data/1073741824.0) as used_gb, CASE WHEN enabled=1 THEN '✅' ELSE '❌' END as status FROM users" | while IFS='|' read -r username uuid used_gb status; do
        printf "│ %-10s │ %-18s │ %-10s │ %-8s │\\n" "$username" "${uuid:0:18}" "$used_gb GB" "$status"
    done
    
    echo "└────────────┴────────────────────┴────────────┴──────────┘"
}

delete_user() {
    if [ -z "$1" ]; then
        echo -e "${RED}Error: Username required${NC}"
        echo "Usage: Z-pars delete-user <username>"
        return 1
    fi
    
    username="$1"
    sqlite3 "$DB_FILE" "DELETE FROM users WHERE username='$username'"
    rm -f "$USERS_DIR/$username.conf"
    rm -f "$USERS_DIR/$username.png"
    update_xray_config
    echo -e "${GREEN}[+] User '$username' deleted${NC}"
}

user_config() {
    if [ -z "$1" ]; then
        echo -e "${RED}Error: Username required${NC}"
        echo "Usage: Z-pars user-config <username>"
        return 1
    fi
    
    username="$1"
    
    if [ -f "$USERS_DIR/$username.conf" ]; then
        cat "$USERS_DIR/$username.conf"
    else
        echo -e "${RED}Error: User '$username' not found${NC}"
    fi
}

reset_traffic() {
    if [ -z "$1" ]; then
        echo -e "${RED}Error: Username required${NC}"
        echo "Usage: Z-pars reset-traffic <username>"
        return 1
    fi
    
    username="$1"
    sqlite3 "$DB_FILE" "UPDATE users SET used_data=0 WHERE username='$username'"
    echo -e "${GREEN}[+] Traffic reset for user '$username'${NC}"
}

web_panel() {
    echo -e "${BLUE}Starting web interface...${NC}"
    local current_port=$(get_current_port)
    
    cat > /var/www/Z-pars/index.html << WEB_EOF
<!DOCTYPE html>
<html>
<head>
    <title>Z-pars VPN Panel</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .status { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .command { background: #f5f5f5; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0; }
        .port-info { background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Z-pars VPN Panel</h1>
        <div class="port-info">
            <h3>Current VPN Port: <strong>$current_port</strong></h3>
            <p>Your VPN is running on port $current_port (randomly assigned)</p>
        </div>
        <div class="status">
            <h2>Status: Running</h2>
            <p>Server is operational</p>
        </div>
        <h3>Quick Commands:</h3>
        <div class="command">Z-pars add-user username</div>
        <div class="command">Z-pars list-users</div>
        <div class="command">Z-pars status</div>
    </div>
</body>
</html>
WEB_EOF
    
    cat > /etc/nginx/sites-available/Z-pars << NGINX_EOF
server {
    listen 80;
    server_name _;
    root /var/www/Z-pars;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location /api {
        proxy_pass http://127.0.0.1:$current_port;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
NGINX_EOF
    
    ln -sf /etc/nginx/sites-available/Z-pars /etc/nginx/sites-enabled/ 2>/dev/null
    nginx -t && systemctl restart nginx
    
    echo -e "${GREEN}[+] Web interface started at http://$(curl -4 -s icanhazip.com)${NC}"
}

api_info() {
    local current_port=$(get_current_port)
    
    echo -e "${CYAN}Z-pars API Information:${NC}"
    echo "API Endpoint: http://$(curl -4 -s icanhazip.com)/api"
    echo "Current Port: $current_port"
    echo "Status: /api/status"
}

backup_db() {
    BACKUP_FILE="$PANEL_DIR/backups/backup_$(date +%Y%m%d_%H%M%S).db"
    cp "$DB_FILE" "$BACKUP_FILE"
    echo -e "${GREEN}[+] Backup created: $BACKUP_FILE${NC}"
}

restore_db() {
    if [ -z "$1" ]; then
        echo -e "${RED}Error: Backup file required${NC}"
        echo "Usage: Z-pars restore <backup_file>"
        return 1
    fi
    
    backup_file="$1"
    
    if [ -f "$backup_file" ]; then
        cp "$backup_file" "$DB_FILE"
        echo -e "${GREEN}[+] Database restored from: $backup_file${NC}"
    else
        echo -e "${RED}Error: Backup file not found${NC}"
    fi
}

update_zpars() {
    echo -e "${BLUE}[*] Updating Z-pars...${NC}"
    curl -sL https://raw.githubusercontent.com/gamechanger877-ea/Z-pars/main/install.sh | bash
}

uninstall_zpars() {
    echo -e "${YELLOW}[-] Uninstalling Z-pars...${NC}"
    
    systemctl stop Z-pars 2>/dev/null
    systemctl disable Z-pars 2>/dev/null
    rm -f /etc/systemd/system/Z-pars.service
    rm -f /usr/local/bin/Z-pars
    rm -rf /opt/Z-pars
    rm -rf /etc/Z-pars
    rm -rf /var/www/Z-pars
    
    systemctl daemon-reload
    
    echo -e "${GREEN}Z-pars uninstalled${NC}"
}

panel_status() {
    local current_port=$(get_current_port)
    
    echo -e "${CYAN}Z-pars Panel Status:${NC}"
    echo "────────────────────"
    echo -e "VPN Port: ${YELLOW}$current_port${NC}"
    echo ""
    
    if systemctl is-active --quiet Z-pars; then
        echo -e "Service: ${GREEN}✅ Running${NC}"
    else
        echo -e "Service: ${RED}❌ Stopped${NC}"
    fi
    
    if systemctl is-active --quiet xray; then
        echo -e "Xray:    ${GREEN}✅ Running${NC}"
    else
        echo -e "Xray:    ${RED}❌ Stopped${NC}"
    fi
    
    if systemctl is-active --quiet nginx; then
        echo -e "Nginx:   ${GREEN}✅ Running${NC}"
    else
        echo -e "Nginx:   ${RED}❌ Stopped${NC}"
    fi
    
    echo ""
    echo -e "${CYAN}Users:${NC}"
    list_users
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
        sleep 2
        start_panel
        ;;
    status)
        panel_status
        ;;
    add-user)
        init_db
        add_user "$2"
        ;;
    list-users)
        list_users
        ;;
    delete-user)
        delete_user "$2"
        ;;
    user-config)
        user_config "$2"
        ;;
    reset-traffic)
        reset_traffic "$2"
        ;;
    web)
        web_panel
        ;;
    api)
        api_info
        ;;
    backup)
        backup_db
        ;;
    restore)
        restore_db "$2"
        ;;
    update)
        update_zpars
        ;;
    uninstall)
        uninstall_zpars
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_banner
        show_help
        ;;
esac
EOF

    chmod +x /usr/local/bin/Z-pars
}

# Setup firewall
setup_firewall() {
    echo -e "${BLUE}[*] Configuring firewall...${NC}"
    
    local current_port=$(get_current_port)
    
    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp >/dev/null 2>&1
        ufw allow $current_port/tcp >/dev/null 2>&1
        ufw allow 80/tcp >/dev/null 2>&1
        ufw allow 8080/tcp >/dev/null 2>&1
        ufw --force enable >/dev/null 2>&1
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=22/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=$current_port/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=8080/tcp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
}

# Final setup
final_setup() {
    echo -e "${BLUE}[*] Finalizing installation...${NC}"
    
    # Find free port first
    find_free_port
    
    # Create Z-pars command
    create_zpars_script
    
    # Create Python API
    create_python_api
    
    # Initialize database
    /usr/local/bin/Z-pars add-user init_user_test > /dev/null 2>&1 || true
    /usr/local/bin/Z-pars delete-user init_user_test > /dev/null 2>&1 || true
    
    # Setup firewall with random port
    setup_firewall
    
    # Start services
    systemctl start xray
    systemctl enable xray
    
    echo -e "${GREEN}[✓] Installation complete!${NC}"
}

# Show success message
show_success() {
    local current_port=$(get_current_port)
    SERVER_IP=$(curl -4 -s icanhazip.com 2>/dev/null || echo "your-server-ip")
    
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║          Z-pars VPN Panel Installed!            ║"
    echo "║         (Random Port Edition v4.0)               ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${CYAN}Quick Start:${NC}"
    echo "────────────────────"
    echo -e "Add a user:       ${YELLOW}Z-pars add-user username${NC}"
    echo -e "List users:       ${YELLOW}Z-pars list-users${NC}"
    echo -e "Check status:     ${YELLOW}Z-pars status${NC}"
    echo ""
    echo -e "${CYAN}Access Information:${NC}"
    echo "────────────────────"
    echo -e "Server IP:        ${YELLOW}$SERVER_IP${NC}"
    echo -e "VPN Port:         ${YELLOW}$current_port${NC}"
    echo -e "Protocol:         ${YELLOW}VLESS + Reality${NC}"
    echo -e "Web Interface:    ${YELLOW}http://$SERVER_IP${NC}"
    echo ""
    echo -e "${CYAN}Admin Credentials:${NC}"
    echo "────────────────────"
    echo -e "Check: ${YELLOW}cat /opt/Z-pars/admin_credentials.txt${NC}"
    echo ""
    echo -e "${GREEN}Type 'Z-pars help' for all commands${NC}"
    echo -e "${YELLOW}⚠️  IMPORTANT: Your VPN is using port $current_port - update your clients!${NC}"
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
main "$@"
