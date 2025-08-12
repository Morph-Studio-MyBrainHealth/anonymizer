#!/bin/bash

# Make script exit on first error
set -e

# Update system packages
sudo apt-get update
sudo apt-get upgrade -y

# Install Python and required system packages
sudo apt-get install -y python3-pip python3-venv nginx

# Create project directory
sudo mkdir -p /home/ubuntu/anonymizer
sudo chown ubuntu:ubuntu /home/ubuntu/anonymizer

# Copy application files
cp -r ./* /home/ubuntu/anonymizer/

# Setup virtual environment
cd /home/ubuntu/anonymizer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Setup systemd service
sudo cp anonymizer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable anonymizer
sudo systemctl start anonymizer

# Setup Nginx
sudo tee /etc/nginx/sites-available/anonymizer << EOF
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

# Enable the Nginx site
sudo ln -sf /etc/nginx/sites-available/anonymizer /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx

echo "Deployment completed successfully!" 