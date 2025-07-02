#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Installing radvan-go systemd service...${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Build the binary
echo -e "${YELLOW}Building radvan-go binary...${NC}"
go build -o radvan-go .

# Install binary
echo -e "${YELLOW}Installing binary to /usr/local/bin/...${NC}"
cp radvan-go /usr/local/bin/
chmod +x /usr/local/bin/radvan-go

# Create config directory
echo -e "${YELLOW}Creating configuration directory...${NC}"
mkdir -p /etc/radvan-go

# Install config file
if [[ ! -f /etc/radvan-go/config.yaml ]]; then
    echo -e "${YELLOW}Installing default configuration...${NC}"
    cp config.yaml /etc/radvan-go/
else
    echo -e "${YELLOW}Configuration file already exists, not overwriting${NC}"
fi

# Install systemd service
echo -e "${YELLOW}Installing systemd service file...${NC}"
cp radvan-go.service /etc/systemd/system/

# Reload systemd
echo -e "${YELLOW}Reloading systemd daemon...${NC}"
systemctl daemon-reload

# Enable service
echo -e "${YELLOW}Enabling radvan-go service...${NC}"
systemctl enable radvan-go

echo -e "${GREEN}Installation complete!${NC}"
echo
echo "Usage:"
echo "  Start service:   systemctl start radvan-go"
echo "  Stop service:    systemctl stop radvan-go"
echo "  Restart service: systemctl restart radvan-go"
echo "  Check status:    systemctl status radvan-go"
echo "  View logs:       journalctl -u radvan-go -f"
echo
echo "Configuration file: /etc/radvan-go/config.yaml"
