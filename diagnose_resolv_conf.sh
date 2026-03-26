#!/bin/bash

echo "=== /etc/resolv.conf Diagnostic Script ==="
echo "Date: $(date)"
echo ""

echo "1. Current /etc/resolv.conf content:"
if [ -f /etc/resolv.conf ]; then
    cat /etc/resolv.conf
else
    echo "ERROR: /etc/resolv.conf does not exist!"
fi
echo ""

echo "2. File permissions and ownership:"
ls -la /etc/resolv.conf 2>/dev/null || echo "File not found"
echo ""

echo "3. Checking if /etc/resolv.conf is a symlink:"
if [ -L /etc/resolv.conf ]; then
    echo "YES - /etc/resolv.conf is a symlink pointing to:"
    readlink /etc/resolv.conf
else
    echo "NO - /etc/resolv.conf is a regular file"
fi
echo ""

echo "4. Checking systemd-resolved status:"
systemctl is-active systemd-resolved 2>/dev/null || echo "systemd-resolved not running"
echo ""

echo "5. Checking /run/systemd/resolve/resolv.conf:"
if [ -f /run/systemd/resolve/resolv.conf ]; then
    echo "Content of /run/systemd/resolve/resolv.conf:"
    cat /run/systemd/resolve/resolv.conf
else
    echo "/run/systemd/resolve/resolv.conf does not exist"
fi
echo ""

echo "6. Checking for other resolv.conf files:"
find /etc -name "*resolv*" -type f 2>/dev/null
echo ""

echo "7. Checking recent modifications to /etc/resolv.conf:"
if [ -f /etc/resolv.conf ]; then
    stat /etc/resolv.conf
fi
echo ""

echo "8. Checking if any processes are writing to /etc/resolv.conf:"
lsof /etc/resolv.conf 2>/dev/null || echo "No processes currently accessing /etc/resolv.conf"
echo ""

echo "9. Checking network manager services:"
systemctl is-active NetworkManager 2>/dev/null || echo "NetworkManager not running"
systemctl is-active networking 2>/dev/null || echo "networking service not running"
echo ""

echo "10. Checking netplan configuration:"
if [ -f /etc/netplan/01-pisowifi-config.yaml ]; then
    echo "Netplan config exists:"
    cat /etc/netplan/01-pisowifi-config.yaml
else
    echo "No netplan config found"
fi
echo ""

echo "=== Diagnostic Complete ==="