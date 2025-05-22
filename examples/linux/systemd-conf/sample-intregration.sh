# Create monitoring service
sudo tee /etc/systemd/system/linux-sigma-ocsf.service << 'EOF'
[Unit]
Description=Linux Security Rule Converter (Sigma to OCSF)
After=network.target

[Service]
Type=simple
User=security
Group=security
WorkingDirectory=/opt/sigma-ocsf
ExecStart=/usr/bin/python3 /opt/sigma-ocsf/linux_monitor.py
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable linux-sigma-ocsf.service
sudo systemctl start linux-sigma-ocsf.service
