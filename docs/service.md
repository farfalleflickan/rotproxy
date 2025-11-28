rotproxy ships with a well hardened systemd service which restricts devices, IP addresses & user/group.

A less restrictive, minimal viable unit would look as follows:

```
[Unit]
Description=rotproxy
After=network.target

[Service]
ExecStart=/usr/bin/rotproxy -c /etc/rotproxy/rotproxy.toml
Restart=on-failure
StandardOutput=append:/var/log/rotproxy/rotproxy.log
StandardError=append:/var/log/rotproxy/rotproxy.log

User=rotproxy
Group=rotproxy

[Install]
WantedBy=multi-user.target
```