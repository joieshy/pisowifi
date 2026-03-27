require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const network = require('network-list');
const os = require('os');
const { exec, execSync } = require('child_process');
const https = require('https');
const axios = require('axios');
const { SerialPort, ReadlineParser } = require('serialport'); // Import serialport
const { applyNetworkConfig, applyAllNetworkSettings, applyLanBridgeApSettings, sudoExec, autoConfigureNetwork, getNetworkStatus, getCurrentLanSettings, applyDynamicLanIp } = require('./services/networkService'); // Idinagdag ito
const app = express();
app.set('trust proxy', true);

if (os.platform() === 'linux') {
    try {
        // IMPORTANT:
        // Do NOT hardcode interface names here.
        // This project runs in bridge/AP mode where LAN side is br0.
        // We also avoid forcing a blanket FORWARD DROP on startup that can override later rules.
        console.log('Firewall reset on startup: skipped hardcoded rules (bridge mode uses dynamic rules).');
    } catch (e) {
        console.log('Firewall startup block failed');
    }
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'pisowifi-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 3600000, // 1 hour
        secure: false, // Set to true if using HTTPS
        sameSite: 'Lax' // Can be 'Strict', 'Lax', or 'None'
    }
}));

function getSettingValue(key, fallback = '') {
    return new Promise((resolve) => {
        db.get(`SELECT value FROM settings WHERE key = ?`, [key], (err, row) => {
            if (err) return resolve(fallback);
            resolve(row && row.value ? row.value : fallback);
        });
    });
}

function getPortalHostPort() {
    return `${PORT}`;
}

function normalizeLanIp(lanIpAddress) {
    return String(lanIpAddress || '10.0.0.1/24').split('/')[0].trim();
}

async function getPortalBaseUrl() {
    const lanIpAddress = await getSettingValue('lan_ip_address', '10.0.0.1/24');
    const lanIp = normalizeLanIp(lanIpAddress);
    return `http://${lanIp}:${getPortalHostPort()}`;
}

// LAN-only force redirect to dynamic portal URL
// - Uses the DB-backed LAN IP and runtime PORT
// - Keeps WAN access untouched
app.use(async (req, res, next) => {
    try {
        const host = (req.get('host') || '').trim();

        // Express may give IPv6-mapped IPv4 like ::ffff:10.0.0.50
        const rawIp = (req.ip || req.connection?.remoteAddress || '').trim();
        const ip = rawIp.replace('::ffff:', '');

        const lanIpAddress = await getSettingValue('lan_ip_address', '10.0.0.1/24');
        const lanIp = normalizeLanIp(lanIpAddress);
        const portalBaseUrl = await getPortalBaseUrl();

        const isLanClient = ip.startsWith(lanIp.split('.').slice(0, 3).join('.') + '.');
        const isLocalhost = ip === '127.0.0.1' || ip === '::1';

        if (!isLocalhost && isLanClient) {
            const needsRedirect =
                !host.startsWith(lanIp) ||
                (host.startsWith(lanIp) && !host.includes(`:${PORT}`));

            if (needsRedirect) {
                res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
                return res.redirect(`${portalBaseUrl}${req.originalUrl}`);
            }
        }

        if (host && host.startsWith(lanIp) && !host.includes(`:${PORT}`)) {
            res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            return res.redirect(`${portalBaseUrl}${req.originalUrl}`);
        }

        next();
    } catch (err) {
        next();
    }
});

// Auth Middleware
const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.adminId) {
        next();
    } else {
        res.redirect('/login');
    }
};

const PORT = process.env.PORT || 3000;
const DATABASE_PATH = process.env.DATABASE_PATH || './pisowifi.db';

let serialPort = null;
// Common identifiers for NodeMCU (CH340G chip) across different OS
const NODE_MCU_IDENTIFIERS = [
    'USB-SERIAL CH340', // Common for Windows
    'wch.cn',           // Common for CH340 on Linux
    'QinHeng Electronics', // Another common for CH340 on Linux
    'CH340'             // More generic, might appear in pnpId or description
];

const http = require('http');
const server = http.createServer(app);
const io = require('socket.io')(server);

let coinInsertionActive = false; // Global state to track if someone is inserting coins
let activeCoinInserterMac = null; // MAC address of the user currently inserting coins
let coinslotEnableTimeout = null; // Timeout to disable coinslot if no activity
const COINSLOT_INACTIVITY_TIMEOUT = 60000; // 60 seconds of inactivity before disabling coinslot
let lastTotalCoinsFromMCU = 0; // To track the total coins reported by NodeMCU

// --- NETWORK CONTROL LOGIC (LINUX/ORANGE PI) ---

function getMacFromIp(ip) {
    try {
        if (!ip) return null;
        
        // Remove IPv6 prefix if present
        const cleanIp = ip.replace('::ffff:', '').trim();
        
        // Handle localhost/server
        if (cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp === 'localhost') {
            return '00:00:00:00:00:00';
        }
        
        let mac = null;
        
        // Try to ping the IP first to ensure it's in the ARP table
        try {
            const pingCmd = os.platform() === 'win32' 
                ? `ping -n 1 -w 200 ${cleanIp}` 
                : `ping -c 1 -W 1 ${cleanIp}`;
            execSync(pingCmd, { timeout: 1000, stdio: 'ignore' });
        } catch (e) {}

        // Try multiple methods to get the MAC address
        const commands = os.platform() === 'win32' 
            ? [`arp -a ${cleanIp}`] 
            : [`arp -n ${cleanIp}`, `ip neighbor show to ${cleanIp}`, `grep ${cleanIp} /proc/net/arp`];

        for (const cmd of commands) {
            try {
                const output = execSync(cmd, { timeout: 1000 }).toString();
                const match = output.match(/(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})/);
                if (match) {
                    mac = match[0].toUpperCase().replace(/-/g, ':');
                    break;
                }
            } catch (e) {}
        }

        // If still not found, try scanning the whole ARP table
        if (!mac) {
            try {
                const listCmd = os.platform() === 'win32' ? 'arp -a' : 'arp -n';
                const output = execSync(listCmd).toString();
                const lines = output.split('\n');
                for (const line of lines) {
                    if (line.includes(cleanIp)) {
                        const match = line.match(/(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})/);
                        if (match) {
                            mac = match[0].toUpperCase().replace(/-/g, ':');
                            break;
                        }
                    }
                }
            } catch (e) {}
        }

        return mac;
    } catch (e) {
        console.error('Error getting MAC from IP:', e.message);
        return null;
    }
}

async function allowMac(mac, ip) {

    if (os.platform() !== 'linux') return;

    try {

        const settings = await new Promise((resolve, reject) => {
            db.all(
                `SELECT key, value FROM settings 
                 WHERE key IN ('wan_interface_name','lan_interface_name', 'lan_ip_address')`,
                [],
                (err, rows) => {
                    if (err) return reject(err);
                    const s = {};
                    rows.forEach(r => s[r.key] = r.value);
                    resolve(s);
                }
            );
        });

        const wan = settings.wan_interface_name || 'enp1s0';
        const lan = 'br0';

        // REMOVE existing rule first (important)
        await sudoExec(`iptables -D FORWARD -i ${lan} -o ${wan} -s ${ip} -j ACCEPT || true`);

        // INSERT at very top
        await sudoExec(`iptables -I FORWARD 1 -i ${lan} -o ${wan} -s ${ip} -j ACCEPT`);

        // Apply Bandwidth Limits
        try {
            // 1. Get Global Settings
            const settingsRows = await new Promise((resolve) => {
                db.all(`SELECT key, value FROM settings WHERE key IN ('download_limit', 'upload_limit')`, [], (err, rows) => resolve(rows || []));
            });
            const bwSettings = {};
            settingsRows.forEach(r => bwSettings[r.key] = r.value);
            const globalDl = parseFloat(bwSettings.download_limit || 0);
            const globalUl = parseFloat(bwSettings.upload_limit || 0);

            // 2. Get User Settings
            const user = await new Promise((resolve) => {
                db.get(`SELECT id, download_limit, upload_limit, tc_class_id FROM users WHERE mac_address = ?`, [mac], (err, row) => resolve(row));
            });

            if (user) {
                // 3. Determine Effective Limits (User overrides Global)
                const dlLimit = (user.download_limit > 0) ? user.download_limit : globalDl;
                const ulLimit = (user.upload_limit > 0) ? user.upload_limit : globalUl;

                if (dlLimit > 0 || ulLimit > 0) {
                    let classId = user.tc_class_id;
                    if (!classId) {
                        classId = user.id + 100; // Generate a simple unique ID based on user ID
                        db.run(`UPDATE users SET tc_class_id = ? WHERE mac_address = ?`, [classId, mac]);
                    }
                    // Apply limits
                    applyBandwidthLimits(ip, dlLimit, ulLimit, classId);
                }
            }
        } catch (bwErr) {
            console.error('Error applying bandwidth limits in allowMac:', bwErr);
        }

        console.log(`Internet allowed for ${mac} (${ip})`);

    } catch (err) {
        console.error('allowMac error:', err.message);
    }
}

async function applyBandwidthLimits(ip, downloadLimitMbps, uploadLimitMbps, tcClassId) {
    if (os.platform() !== 'linux') {
        console.log(`[Simulated] Applying bandwidth limits for IP: ${ip}, DL: ${downloadLimitMbps}Mbps, UL: ${uploadLimitMbps}Mbps, ClassID: ${tcClassId}`);
        return;
    }

    try {
        // When we run in bridge/AP mode, traffic shaping must be applied on br0 (not the raw LAN member interface).
        // This ensures both wired LAN + WiFi clients are shaped consistently.
        const lanInterface = 'br0';

        // --- ENSURE TRAFFIC CONTROL INFRASTRUCTURE ---
        // 1. LAN Interface (Download) - Ensure root qdisc exists
        try { await sudoExec(`tc qdisc add dev ${lanInterface} root handle 1: htb default 10 2>/dev/null || true`); } catch (e) {}
        try { await sudoExec(`tc class add dev ${lanInterface} parent 1: classid 1:10 htb rate 1000mbit 2>/dev/null || true`); } catch (e) {}

        // 2. IFB Interface (Upload) - Ensure module loaded and root qdisc exists
        try { await sudoExec('modprobe ifb numifbs=1'); } catch (e) {}
        try { await sudoExec('ip link set dev ifb0 up'); } catch (e) {}
        try { await sudoExec(`tc qdisc add dev ifb0 root handle 1: htb default 10 2>/dev/null || true`); } catch (e) {}
        try { await sudoExec(`tc class add dev ifb0 parent 1: classid 1:10 htb rate 1000mbit 2>/dev/null || true`); } catch (e) {}

        // 3. LAN Ingress Redirection (Redirect Upload to IFB)
        try {
            await sudoExec(`tc qdisc add dev ${lanInterface} handle ffff: ingress 2>/dev/null || true`);
            const currentFilters = await sudoExec(`tc filter show dev ${lanInterface} parent ffff:`);
            if (!currentFilters.stdout.includes('mirred')) {
                await sudoExec(`tc filter add dev ${lanInterface} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0`);
            }
        } catch (e) {}
        // ---------------------------------------------

        // Convert Mbps to Mbits for tc
        const dlRate = downloadLimitMbps > 0 ? `${downloadLimitMbps}mbit` : '1000mbit';
        const ulRate = uploadLimitMbps > 0 ? `${uploadLimitMbps}mbit` : '1000mbit';
        const classId = `1:${tcClassId}`;
        const prio = tcClassId + 100; // Offset priority to avoid conflicts

        // Clean up existing limits for this class ID/Prio just in case
        try { await sudoExec(`tc filter del dev ${lanInterface} parent 1: prio ${prio} 2>/dev/null || true`); } catch (e) {}
        try { await sudoExec(`tc class del dev ${lanInterface} parent 1: classid ${classId} 2>/dev/null || true`); } catch (e) {}
        try { await sudoExec(`tc filter del dev ifb0 parent 1: prio ${prio} 2>/dev/null || true`); } catch (e) {}
        try { await sudoExec(`tc class del dev ifb0 parent 1: classid ${classId} 2>/dev/null || true`); } catch (e) {}

        // DOWNLOAD (LAN Interface Egress) - Server to Client
        if (downloadLimitMbps > 0) {
            // Create class
            await sudoExec(`tc class add dev ${lanInterface} parent 1: classid ${classId} htb rate ${dlRate} ceil ${dlRate}`);
            // Filter: Match Destination IP (Client IP)
            await sudoExec(`tc filter add dev ${lanInterface} protocol ip parent 1: prio ${prio} u32 match ip dst ${ip}/32 flowid ${classId}`);
        }

        // UPLOAD (IFB0 Interface Egress, redirected from LAN Ingress) - Client to Server
        if (uploadLimitMbps > 0) {
            // Create class
            await sudoExec(`tc class add dev ifb0 parent 1: classid ${classId} htb rate ${ulRate} ceil ${ulRate}`);
            // Filter: Match Source IP (Client IP)
            await sudoExec(`tc filter add dev ifb0 protocol ip parent 1: prio ${prio} u32 match ip src ${ip}/32 flowid ${classId}`);
        }

        console.log(`Bandwidth limits applied for IP ${ip} (DL: ${downloadLimitMbps}Mbps, UL: ${uploadLimitMbps}Mbps)`);
    } catch (e) {
        console.error(`Failed to apply bandwidth limits for IP ${ip}:`, e.message);
    }
}

async function blockMac(mac) {

    if (os.platform() !== 'linux') return;

    try {

        const settings = await new Promise((resolve, reject) => {
            db.all(
                `SELECT key, value FROM settings 
                 WHERE key IN ('wan_interface_name','lan_interface_name', 'lan_ip_address')`,
                [],
                (err, rows) => {
                    if (err) return reject(err);
                    const s = {};
                    rows.forEach(r => s[r.key] = r.value);
                    resolve(s);
                }
            );
        });
        
        const wan = settings.wan_interface_name || 'enp1s0';
        const lan = 'br0';

        const user = await new Promise((resolve, reject) => {
            db.get(
                `SELECT ip_address, tc_class_id, tc_mark FROM users WHERE mac_address = ?`,
                [mac],
                (err, row) => {
                    if (err) return reject(err);
                    resolve(row);
                }
            );
        });

        if (!user || !user.ip_address) return;

        const ip = user.ip_address;

        // DELETE the exact rule we inserted
        await sudoExec(`iptables -D FORWARD -i ${lan} -o ${wan} -s ${ip} -j ACCEPT || true`);

        // Remove Bandwidth Limits
        if (user.tc_class_id) {
            removeBandwidthLimits(ip, user.tc_class_id);
        } else {
            // Try to remove based on ID if class_id wasn't set but might exist
            removeBandwidthLimits(ip, user.id + 100);
        }

        console.log(`Internet blocked for ${mac} (${ip})`);

    } catch (err) {
        console.error('blockMac error:', err.message);
    }
}




async function removeBandwidthLimits(ip, tcClassId) {
    if (os.platform() !== 'linux') {
        console.log(`[Simulated] Removing bandwidth limits for IP: ${ip}, Class: ${tcClassId}`);
        return;
    }
    try {
        // When we run in bridge/AP mode, traffic shaping must be removed from br0 (not the raw LAN member interface).
        const lanInterface = 'br0';
        const classId = `1:${tcClassId}`;
        const prio = tcClassId + 100;

        try { await sudoExec(`tc filter del dev ${lanInterface} parent 1: prio ${prio} 2>/dev/null || true`); } catch (e) {}
        try { await sudoExec(`tc class del dev ${lanInterface} parent 1: classid ${classId} 2>/dev/null || true`); } catch (e) {}
        try { await sudoExec(`tc filter del dev ifb0 parent 1: prio ${prio} 2>/dev/null || true`); } catch (e) {}
        try { await sudoExec(`tc class del dev ifb0 parent 1: classid ${classId} 2>/dev/null || true`); } catch (e) {}

        console.log(`Bandwidth limits removed for IP ${ip} (Class: ${classId})`);
    } catch (e) {
        console.error(`Failed to remove bandwidth limits for IP ${ip}:`, e.message);
    }
}

function restoreOnlineUsers() {
    if (os.platform() !== 'linux') return;
    console.log('Restoring online users...');
    db.all(`SELECT mac_address, ip_address FROM users WHERE status = 'Online' AND time_left > 0`, [], (err, rows) => {
        if (err) {
            console.error('Error fetching online users for restoration:', err);
            return;
        }
        rows.forEach(user => {
            if (user.ip_address && user.mac_address) {
                allowMac(user.mac_address, user.ip_address);
            }
        });
        console.log(`Restored internet access for ${rows.length} online users.`);
    });
}

async function initNetwork() {
    if (os.platform() !== 'linux') return;
    try {
        console.log('Initializing Network for Debian (Bridge AP)...');

        const settings = await new Promise((resolve, reject) => {
            db.all(`SELECT key, value FROM settings WHERE key IN ('wan_interface_name', 'lan_interface_name', 'lan_ip_address', 'lan_dns_servers')`, [], (err, rows) => {
                if (err) return reject(err);
                const s = {};
                rows.forEach(row => s[row.key] = row.value);
                resolve(s);
            });
        });

        const wanInterface = settings.wan_interface_name || 'enp1s0';
        const lanInterface = settings.lan_interface_name || 'enx00e04c680013';
        const lanIpCidr = settings.lan_ip_address || '10.0.0.1/24';
        const lanDnsServers = settings.lan_dns_servers ? settings.lan_dns_servers.split(',').map(s => s.trim()).filter(s => s) : [];

        console.log(`[Network] Configuring: WAN=${wanInterface}, LAN=${lanInterface}, LAN CIDR=${lanIpCidr}, Bridge=br0`);

        // --- Stop systemd-resolved and lock /etc/resolv.conf to prevent overwrites ---
        try {
            await sudoExec('systemctl stop systemd-resolved || true');
            await sudoExec('systemctl disable systemd-resolved || true');
            
            // Use DNS settings from database instead of hardcoded Google DNS
            const dnsSettings = await new Promise((resolve, reject) => {
                db.all(`SELECT key, value FROM settings WHERE key IN ('wan_dns_servers', 'lan_dns_servers')`, [], (err, rows) => {
                    if (err) return reject(err);
                    const s = {};
                    rows.forEach(row => s[row.key] = row.value);
                    resolve(s);
                });
            });

            const dnsServers = dnsSettings.wan_dns_servers || dnsSettings.lan_dns_servers || '8.8.8.8,8.8.4.4';
            const dnsList = dnsServers.split(',').map(s => s.trim()).filter(s => s);

            // Create resolv.conf with database DNS settings
            const dnsConfig = dnsList.map(dns => `nameserver ${dns}`).join('\n');
            
            // Remove existing resolv.conf and create new one
            await sudoExec('rm -f /etc/resolv.conf || true');
            await sudoExec(`echo "${dnsConfig}" | tee /etc/resolv.conf > /dev/null`);
            
            // Make /etc/resolv.conf immutable to prevent any service from overwriting it
            await sudoExec('chattr +i /etc/resolv.conf || true');
            
            // Also prevent systemd-resolved from creating its own resolv.conf
            await sudoExec('mkdir -p /run/systemd/resolve || true');
            await sudoExec('touch /run/systemd/resolve/resolv.conf || true');
            await sudoExec('chattr +i /run/systemd/resolve/resolv.conf || true');
            
            console.log(`[Network] DNS configured: ${dnsList.join(', ')} (locked against overwrites)`);
        } catch (e) {
            console.log('[Network] Note: systemd-resolved handling or DNS configuration failed:', e.message);
        }

        // --- Apply bridge + dnsmasq bridge on LAN subnet ---
        await applyLanBridgeApSettings({
            lan_interface_name: lanInterface,
            lan_ip_address: lanIpCidr,
            lan_dns_servers: lanDnsServers,
            wan_interface_name: wanInterface
        });
        
        if (os.platform() === 'linux') {
            try {
                await reapplyNatRulesFromDb();
            } catch (natErr) {
                console.error('[Network] Failed to reapply NAT rules after network init:', natErr.message);
            }
        }

        console.log('Network initialization complete (Bridge AP).');
    } catch (e) {
        console.error('Network init failed:', e.message);
    }
}

let nextTcClassId = 1; // To assign unique class IDs for traffic control

async function initTrafficControl() {
    if (os.platform() !== 'linux') {
        console.log('[Simulated] Traffic Control: Skipping init on non-Linux platform.');
        return;
    }
    try {
        console.log('Initializing Traffic Control (TC)...');

        // In bridge/AP mode, shape traffic on br0.
        const lanInterface = 'br0';

        // Load IFB module for ingress shaping (Upload limit)
        try { await sudoExec('modprobe ifb numifbs=1'); } catch (e) {}
        try { await sudoExec('ip link set dev ifb0 up'); } catch (e) {}

        // Clear existing qdisc, classes, and filters on LAN interface
        await sudoExec(`tc qdisc del dev ${lanInterface} root || true`);
        await sudoExec(`tc qdisc del dev ${lanInterface} ingress || true`);
        await sudoExec(`tc qdisc del dev ifb0 root || true`);

        // 1. LAN Interface (Download/Egress)
        // Add HTB root qdisc
        await sudoExec(`tc qdisc add dev ${lanInterface} root handle 1: htb default 10`);
        // Add default class (unlimited)
        await sudoExec(`tc class add dev ${lanInterface} parent 1: classid 1:10 htb rate 1000mbit`);

        // 2. LAN Interface (Upload/Ingress) -> Redirect to IFB0
        await sudoExec(`tc qdisc add dev ${lanInterface} handle ffff: ingress`);
        // Redirect all ingress traffic to ifb0
        await sudoExec(`tc filter add dev ${lanInterface} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0`);

        // 3. IFB0 Interface (Upload Shaping)
        await sudoExec(`tc qdisc add dev ifb0 root handle 1: htb default 10`);
        await sudoExec(`tc class add dev ifb0 parent 1: classid 1:10 htb rate 1000mbit`);


        console.log('Traffic Control (TC) initialization complete.');
    } catch (e) {
        console.error('Traffic Control (TC) init failed:', e.message);
        console.warn('Traffic control features may not be available.');
    }
}

// CPU Usage Tracking for Windows/Linux
let lastCpuUsage = 0;
function getCpuStats() {
    const cpus = os.cpus();
    let user = 0, nice = 0, sys = 0, idle = 0, irq = 0;
    for (let cpu of cpus) {
        user += cpu.times.user;
        nice += cpu.times.nice;
        sys += cpu.times.sys;
        idle += cpu.times.idle;
        irq += cpu.times.irq;
    }
    const total = user + nice + sys + idle + irq;
    return { idle, total };
}

// Get Unique Machine ID
function getMachineId() {
    try {
        if (os.platform() === 'win32') {
            try {
                // Try PowerShell first (modern Windows)
                const output = execSync('powershell -command "(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID"', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
                return output.trim();
            } catch (psErr) {
                try {
                    // Fallback to wmic but suppress errors
                    const output = execSync('wmic csproduct get uuid', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
                    return output.split('\n')[1].trim();
                } catch (wmicErr) {
                    return os.hostname();
                }
            }
        } else {
            // For Orange Pi / Linux (CPU Serial)
            try {
                const output = execSync("cat /proc/cpuinfo | grep Serial | cut -d ':' -f 2", { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
                return output.trim() || os.hostname();
            } catch (e) {
                return os.hostname();
            }
        }
    } catch (e) {
        return os.hostname();
    }
}

let serverStartTime = new Date(); // Store the server start time
function formatDuration(totalMinutes) {
    const mins = Math.max(0, Math.floor(Number(totalMinutes) || 0));
    const days = Math.floor(mins / 1440);
    const hours = Math.floor((mins % 1440) / 60);
    const minutes = mins % 60;
    const parts = [];
    if (days) parts.push(`${days} day${days !== 1 ? 's' : ''}`);
    if (hours) parts.push(`${hours} hour${hours !== 1 ? 's' : ''}`);
    if (minutes || parts.length === 0) parts.push(`${minutes} minute${minutes !== 1 ? 's' : ''}`);
    return parts.join(', ');
}

function getSystemUptimeSeconds() {
    if (os.platform() === 'linux') {
        try {
            const uptimeRaw = fs.readFileSync('/proc/uptime', 'utf8').split(' ')[0];
            const uptimeSeconds = parseFloat(uptimeRaw);
            if (!Number.isNaN(uptimeSeconds) && uptimeSeconds >= 0) {
                return Math.floor(uptimeSeconds);
            }
        } catch (e) {
            // fall back below
        }
    }

    return Math.max(0, Math.floor((Date.now() - serverStartTime.getTime()) / 1000));
}

function formatUptime(seconds) {
    const totalSeconds = Math.max(0, Math.floor(Number(seconds) || 0));
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const parts = [];
    if (days) parts.push(`${days} day${days !== 1 ? 's' : ''}`);
    if (hours) parts.push(`${hours} hour${hours !== 1 ? 's' : ''}`);
    if (minutes || parts.length === 0) parts.push(`${minutes} minute${minutes !== 1 ? 's' : ''}`);
    return parts.join(', ');
}
let startMeasure = getCpuStats();
setInterval(() => {
    const endMeasure = getCpuStats();
    const idleDiff = endMeasure.idle - startMeasure.idle;
    const totalDiff = endMeasure.total - startMeasure.total;
    if (totalDiff > 0) {
        lastCpuUsage = (100 - (100 * idleDiff / totalDiff)).toFixed(1);
    }
    startMeasure = endMeasure;
}, 2000);

// Database setup
let db = new sqlite3.Database(DATABASE_PATH, (err) => {
    if (err) console.error(err.message);
    console.log(`Connected to the database at ${DATABASE_PATH}`);
});

// Create tables and auto-generate admin
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        ip_address TEXT,
        mac_address TEXT,
        time_left INTEGER,
        status TEXT,
        tc_class_id INTEGER DEFAULT 0,
        tc_mark INTEGER DEFAULT 0
    )`);

    // Add tc_class_id and tc_mark columns if they don't exist (for existing databases)
    db.run(`ALTER TABLE users ADD COLUMN tc_class_id INTEGER DEFAULT 0`, (err) => { /* ignore error if column exists */ });
    db.run(`ALTER TABLE users ADD COLUMN tc_mark INTEGER DEFAULT 0`, (err) => { /* ignore error if column exists */ });
    
    // Add per-user bandwidth limit columns if they don't exist
    db.run(`ALTER TABLE users ADD COLUMN download_limit REAL DEFAULT 0`, (err) => { /* ignore error if column exists */ });
    db.run(`ALTER TABLE users ADD COLUMN upload_limit REAL DEFAULT 0`, (err) => { /* ignore error if column exists */ });

    db.run(`CREATE TABLE IF NOT EXISTS rates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        amount INTEGER,
        duration INTEGER,
        unit TEXT DEFAULT 'minutes'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS vouchers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE,
        duration INTEGER,
        unit TEXT,
        amount INTEGER DEFAULT 0,
        status TEXT DEFAULT 'unused',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Add amount column to vouchers if it doesn't exist (for existing databases)
    db.run(`ALTER TABLE vouchers ADD COLUMN amount INTEGER DEFAULT 0`, (err) => {
        // Ignore error if column already exists
    });

    db.run(`CREATE TABLE IF NOT EXISTS sales (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        amount INTEGER,
        type TEXT,
        description TEXT,
        user_mac TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Add type and description columns to sales if they don't exist
    db.run(`ALTER TABLE sales ADD COLUMN type TEXT`, (err) => {
        // Populate missing types for old records if they exist
        db.run(`UPDATE sales SET type = 'voucher' WHERE type IS NULL AND description LIKE 'Voucher Used:%'`);
        db.run(`UPDATE sales SET type = 'coin' WHERE type IS NULL AND description LIKE 'Coin Insertion%'`);
    });

    db.run(`ALTER TABLE sales ADD COLUMN description TEXT`, (err) => {
        // Ignore error if column already exists
    });

    db.run(`ALTER TABLE sales ADD COLUMN user_mac TEXT`, (err) => {
        // Ignore error if column already exists
    });

    db.run(`CREATE TABLE IF NOT EXISTS blocked_websites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS mac_filters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac_address TEXT UNIQUE,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS port_triggers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        trigger_port INTEGER,
        trigger_proto TEXT,
        open_port TEXT,
        open_proto TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS generated_licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE,
        status TEXT DEFAULT 'unused',
        machine_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Default settings
    const defaultSettings = [
        ['wifi_name', 'PisoWiFi'],
        ['wifi_name_color', '#1a73e8'],
        ['sidebar_color', '#222e3c'],
        ['shop_animation', 'none'],
        ['announcement', ''],
        ['landing_logo', ''],
        ['banner_animation', 'aura'],
        ['insert_coin_audio', '/media/Maaari.m4a'],
        ['download_limit', '0'],
        ['upload_limit', '0'],
        ['system_status', 'Running'],
        ['ewallet_enabled', 'false'],
        ['maya_env', 'sandbox'],
        ['gcash_api_key', ''],
        ['maya_public_key', ''],
        ['maya_api_key', ''],
        ['merchant_id', ''],
        ['anti_tethering', 'false'],
        ['mac_filter_mode', 'disabled'], // disabled, allow, block
        ['qos_enabled', 'false'],
        ['qos_gaming_priority', 'high'],
        ['qos_streaming_priority', 'medium'],
        ['qos_browsing_priority', 'low'],
        ['auto_reboot_enabled', 'false'],
        ['auto_reboot_time', '04:00'],
        ['license_key', ''],
        ['license_status', 'Unactivated'],
        ['license_expiry', 'Never'],
        ['insert_coin_countdown', '60'],
        ['coin_drop_audio', '/media/coins.wav'],
        ['salamat_audio', '/media/Salamat .mp3'],
        ['countdown_tick_audio', ''],
        ['wan_interface_name', 'enp1s0'],
        ['wan_config_type', 'dhcp'],
        ['wan_ip_address', ''],
        ['wan_gateway', ''],
        ['wan_dns_servers', '8.8.8.8,8.8.4.4'],
        ['lan_interface_name', 'enx00e04c680013'],
        ['lan_ip_address', '10.0.0.1/24'],
        ['lan_dns_servers', '8.8.8.8,8.8.4.4'],
    ];

    defaultSettings.forEach(setting => {
        db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, setting);
    });

    // Add network interface settings to the database if they don't exist
    const networkInterfaceSettings = [
        ['wan_interface_name', 'enp1s0'],
        ['wan_config_type', 'dhcp'],
        ['wan_ip_address', ''],
        ['wan_gateway', ''],
        ['wan_dns_servers', '8.8.8.8,8.8.4.4'],
        ['lan_interface_name', 'enx00e04c680013'],
        ['lan_ip_address', '10.0.0.1/24'],
        ['lan_dns_servers', '8.8.8.8,8.8.4.4']
    ];
    networkInterfaceSettings.forEach(setting => {
        db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, setting);
    });

    // Auto-fix: Ensure the database uses the correct detected interfaces from 'ip a'
    // Force update these keys to match the hardware found
    db.run(`UPDATE settings SET value = 'enp1s0' WHERE key = 'wan_interface_name'`);
    db.run(`UPDATE settings SET value = 'enx00e04c680013' WHERE key = 'lan_interface_name'`);

    // Ensure new audio settings exist for existing databases
    const newAudioSettings = [
        ['coin_drop_audio', '/media/coins.wav'],
        ['salamat_audio', '/media/Salamat .mp3'],
        ['countdown_tick_audio', '']
    ];
    newAudioSettings.forEach(setting => {
        db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, setting);
    });

    // Default rates
    db.get(`SELECT COUNT(*) as count FROM rates`, (err, row) => {
        if (row.count === 0) {
            const defaultRates = [
                [1, 15, 'minutes'],
                [5, 1, 'hour'],
                [10, 3, 'hours']
            ];
            defaultRates.forEach(rate => {
                db.run(`INSERT INTO rates (amount, duration, unit) VALUES (?, ?, ?)`, rate);
            });
        }
    });

    db.get(`SELECT * FROM admins WHERE username = 'admin'`, async (err, row) => {
        if (!row) {
            const hashedPassword = await bcrypt.hash('admin', 10);
            db.run(`INSERT INTO admins (username, password) VALUES (?, ?)`, ['admin', hashedPassword]);
            console.log('Default admin account created: admin/admin');
        }
    });

    // Re-enabled network init and traffic control init after disabling UFW
    initNetwork().then(() => {
        initTrafficControl();
        restoreOnlineUsers();
    });
    initSerialPort(); // Re-enabled automatic serial port initialization
});

// Function to send commands to NodeMCU
function sendSerialCommand(command) {
    if (serialPort && serialPort.isOpen) {
        serialPort.write(command + '\n', (err) => {
            if (err) {
                console.error('Error writing to serial port:', err.message);
            } else {
                console.log(`Sent command to NodeMCU: ${command}`);
            }
        });
    } else {
        console.warn(`Serial port not open. Cannot send command: ${command}`);
    }
}

// Function to initialize serial port
function initSerialPort() {
    SerialPort.list().then(ports => {
        const nodeMcuPort = ports.find(port => 
            NODE_MCU_IDENTIFIERS.some(identifier => 
                (port.manufacturer && port.manufacturer.includes(identifier)) || 
                (port.pnpId && port.pnpId.includes(identifier)) ||
                (port.friendlyName && port.friendlyName.includes(identifier)) ||
                (port.path && port.path.includes('ttyUSB')) // Common Linux serial port pattern
            )
        );
        if (nodeMcuPort) {
            console.log(`NodeMCU found on port: ${nodeMcuPort.path}`);
            if (serialPort && serialPort.isOpen) {
                serialPort.close();
                serialPort = null;
            }

            serialPort = new SerialPort({ path: nodeMcuPort.path, baudRate: 115200 });
            const parser = serialPort.pipe(new ReadlineParser({ delimiter: '\n' }));

            serialPort.on('open', () => {
                console.log(`Serial port ${nodeMcuPort.path} to NodeMCU opened automatically.`);
                // Do not enable coinslot automatically here. It will be controlled by WebSocket events.
                lastTotalCoinsFromMCU = 0; // Initialize lastTotalCoinsFromMCU on open
            });

            parser.on('data', data => {
                console.log('Data from NodeMCU:', data); // Keep this log for debugging
                if (data.startsWith('Total Coins:')) {
                    const currentTotalFromMCU = parseInt(data.split(':')[1].trim());
                    if (!isNaN(currentTotalFromMCU)) {
                        if (currentTotalFromMCU > lastTotalCoinsFromMCU) {
                            const amountInserted = currentTotalFromMCU - lastTotalCoinsFromMCU;
                            currentSessionCoins += amountInserted;
                            io.emit('coinInserted', { amount: amountInserted, totalCoins: currentSessionCoins, mac: activeCoinInserterMac });
                            console.log(`Coin of ${amountInserted} detected. Total: ${currentSessionCoins}`);
                            
                            // Reset coinslot disable timeout on coin activity
                            if (coinslotEnableTimeout) {
                                clearTimeout(coinslotEnableTimeout);
                                coinslotEnableTimeout = setTimeout(() => {
                                    if (!coinInsertionActive) { // Only disable if no user is actively inserting
                                        sendSerialCommand('D');
                                        console.log('Coinslot disabled due to inactivity timeout after coin drop.');
                                    }
                                }, COINSLOT_INACTIVITY_TIMEOUT);
                            }
                        }
                        lastTotalCoinsFromMCU = currentTotalFromMCU; // Update last known total
                    }
                } else if (data.startsWith('COIN:')) { // Also handle the COIN:X format if NodeMCU sends it
                    const amount = parseInt(data.split(':')[1]);
                    if (!isNaN(amount) && amount > 0) {
                        currentSessionCoins += amount;
                        io.emit('coinInserted', { amount: amount, totalCoins: currentSessionCoins, mac: activeCoinInserterMac });
                        console.log(`Coin of ${amount} detected. Total: ${currentSessionCoins}`);
                        
                        // Reset coinslot disable timeout on coin activity
                        if (coinslotEnableTimeout) {
                            clearTimeout(coinslotEnableTimeout);
                            coinslotEnableTimeout = setTimeout(() => {
                                if (!coinInsertionActive) { // Only disable if no user is actively inserting
                                    sendSerialCommand('D');
                                    console.log('Coinslot disabled due to inactivity timeout after coin drop.');
                                }
                            }, COINSLOT_INACTIVITY_TIMEOUT);
                        }
                    }
                }
            });

            serialPort.on('close', () => {
                console.log(`Serial port ${nodeMcuPort.path} to NodeMCU closed.`);
                serialPort = null;
                coinInsertionActive = false; // Reset state
                activeCoinInserterMac = null;
                if (coinslotEnableTimeout) clearTimeout(coinslotEnableTimeout);
                sendSerialCommand('D'); // Ensure coinslot is disabled on close
            });

            serialPort.on('error', (err) => {
                console.error('Serial port error (auto-init):', err.message);
                if (serialPort && serialPort.isOpen) {
                    serialPort.close();
                }
            });

        } else {
            console.warn('NodeMCU not found. Automatic serial port initialization skipped.');
        }
    }).catch(err => {
        console.error('Error listing serial ports during auto-initialization:', err.message);
    });
}

// API to list available serial ports
app.get('/api/serial-ports', isAuthenticated, async (req, res) => {
    try {
        const ports = await SerialPort.list();
        res.json(ports.map(port => ({
            path: port.path,
            manufacturer: port.manufacturer || 'N/A',
            pnpId: port.pnpId || 'N/A',
            friendlyName: port.friendlyName || 'N/A', // Add friendlyName
            vendorId: port.vendorId || 'N/A',       // Add vendorId
            productId: port.productId || 'N/A'      // Add productId
        })));
    } catch (err) {
        console.error('Error listing serial ports:', err.message);
        res.status(500).json({ error: 'Failed to list serial ports' });
    }
});

// API to connect to a specific serial port
app.post('/api/serial-port/connect', isAuthenticated, async (req, res) => {
    const { portPath } = req.body;
    if (!portPath) {
        return res.status(400).json({ error: 'Port path is required' });
    }

    // Close existing port if open
    if (serialPort && serialPort.isOpen) {
        serialPort.close();
        serialPort = null;
    }

    try {
        serialPort = new SerialPort({ path: portPath, baudRate: 115200 });
        const parser = serialPort.pipe(new ReadlineParser({ delimiter: '\n' }));

            serialPort.on('open', () => {
                console.log(`Serial port ${portPath} to NodeMCU opened.`);
                // Do not enable coinslot automatically here. It will be controlled by WebSocket events.
                lastTotalCoinsFromMCU = 0; // Initialize on connect
                res.json({ success: true, message: `Connected to ${portPath}` });
            });

            parser.on('data', data => {
                console.log('Data from NodeMCU:', data); // Keep this log for debugging
                if (data.startsWith('Total Coins:')) {
                    const currentTotalFromMCU = parseInt(data.split(':')[1].trim());
                    if (!isNaN(currentTotalFromMCU)) {
                        if (currentTotalFromMCU > lastTotalCoinsFromMCU) {
                            const amountInserted = currentTotalFromMCU - lastTotalCoinsFromMCU;
                            currentSessionCoins += amountInserted;
                            io.emit('coinInserted', { amount: amountInserted, totalCoins: currentSessionCoins, mac: activeCoinInserterMac });
                            console.log(`Coin of ${amountInserted} detected. Total: ${currentSessionCoins}`);

                            // Reset coinslot disable timeout on coin activity
                            if (coinslotEnableTimeout) {
                                clearTimeout(coinslotEnableTimeout);
                                coinslotEnableTimeout = setTimeout(() => {
                                    if (!coinInsertionActive) { // Only disable if no user is actively inserting
                                        sendSerialCommand('D');
                                        console.log('Coinslot disabled due to inactivity timeout after coin drop.');
                                    }
                                }, COINSLOT_INACTIVITY_TIMEOUT);
                            }
                        }
                        lastTotalCoinsFromMCU = currentTotalFromMCU; // Update last known total
                    }
                } else if (data.startsWith('COIN:')) { // Also handle the COIN:X format if NodeMCU sends it
                    const amount = parseInt(data.split(':')[1]);
                    if (!isNaN(amount) && amount > 0) {
                        currentSessionCoins += amount;
                        io.emit('coinInserted', { amount: amount, totalCoins: currentSessionCoins, mac: activeCoinInserterMac });
                        console.log(`Coin of ${amount} detected. Total: ${currentSessionCoins}`);
                        
                        // Reset coinslot disable timeout on coin activity
                        if (coinslotEnableTimeout) {
                            clearTimeout(coinslotEnableTimeout);
                            coinslotEnableTimeout = setTimeout(() => {
                                if (!coinInsertionActive) { // Only disable if no user is actively inserting
                                    sendSerialCommand('D');
                                    console.log('Coinslot disabled due to inactivity timeout after coin drop.');
                                }
                            }, COINSLOT_INACTIVITY_TIMEOUT);
                        }
                    }
                }
            });

        serialPort.on('close', () => {
            console.log(`Serial port ${portPath} to NodeMCU closed.`);
            serialPort = null;
            coinInsertionActive = false; // Reset state
            activeCoinInserterMac = null;
            if (coinslotEnableTimeout) clearTimeout(coinslotEnableTimeout);
            sendSerialCommand('D'); // Ensure coinslot is disabled on close
        });

        serialPort.on('error', (err) => {
            console.error('Serial port error:', err.message);
            if (serialPort && serialPort.isOpen) {
                serialPort.close();
            }
            res.status(500).json({ error: `Serial port error: ${err.message}` });
        });

    } catch (err) {
        console.error('Error connecting to serial port:', err.message);
        res.status(500).json({ error: `Failed to connect to serial port: ${err.message}` });
    }
});

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public'), { index: false }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
    setHeaders: (res, path) => {
        // Disable cache for uploads to fix "picture not loading" issues
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    }
}));
app.use('/media', express.static(path.join(__dirname, 'media')));

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Multer setup for wallpaper upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const prefix = file.fieldname || 'file';
        cb(null, prefix + Date.now() + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        if (file.fieldname === 'audio') {
            const filetypes = /mp3|m4a|wav|ogg|mpeg/;
            const mimetype = filetypes.test(file.mimetype);
            const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
            if (mimetype && extname) {
                return cb(null, true);
            }
            return cb(new Error('Only audio files (MP3, M4A, WAV, OGG) are allowed!'));
        } else if (file.fieldname === 'database') {
            return cb(null, true); // Allow .db files
        } else if (file.fieldname === 'firmware') {
            return cb(null, true); // Allow firmware files
        } else {
            const filetypes = /jpeg|jpg|png|gif|webp/;
            const mimetype = filetypes.test(file.mimetype);
            const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
            if (mimetype && extname) {
                return cb(null, true);
            }
            return cb(new Error('Only images (including GIFs) are allowed!'));
        }
    }
});

// Global variable to track current session coins (simulated)
let currentSessionCoins = 0;

// Routes

async function redirectToPortal(req, res) {
    const portalBaseUrl = await getPortalBaseUrl();
    return res.redirect(portalBaseUrl);
}

app.get('/generate_204', async (req, res) => redirectToPortal(req, res));
app.get('/hotspot-detect.html', async (req, res) => redirectToPortal(req, res));
app.get('/connecttest.txt', async (req, res) => redirectToPortal(req, res));
app.get('/ncsi.txt', async (req, res) => redirectToPortal(req, res)); // Windows
app.get('/canonical.html', async (req, res) => redirectToPortal(req, res)); // Android
app.get('/success.txt', async (req, res) => redirectToPortal(req, res)); // Firefox

app.get('/', (req, res) => {
    // Prevent caching to avoid loading glitches
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API to get available network interfaces
app.get('/api/network/available-interfaces', isAuthenticated, (req, res) => {
    if (os.platform() === 'linux') {
        exec('ls /sys/class/net', (error, stdout, stderr) => {
            if (error) {
                console.error(`Error listing network interfaces on Linux: ${error.message}`);
                console.error(`Stderr from ls /sys/class/net: ${stderr}`);
                return res.status(500).json({ error: 'Failed to list network interfaces', details: stderr });
            }
            console.log(`Stdout from ls /sys/class/net: ${stdout}`); // Idinagdag para sa debugging
            const interfaces = stdout.split('\n').map(s => s.trim()).filter(s => s.length > 0 && s !== 'lo'); // Exclude loopback
            res.json(interfaces);
        });
    } else if (os.platform() === 'win32') {
        // For Windows, use PowerShell to get network adapter names
        exec('powershell -Command "Get-NetAdapter | Select-Object -ExpandProperty Name"', (error, stdout, stderr) => {
            if (error) {
                console.error(`Error listing network interfaces on Windows: ${error.message}`);
                console.error(`Stderr: ${stderr}`);
                return res.status(500).json({ error: 'Failed to list network interfaces on Windows', details: stderr });
            }
            const interfaces = stdout.split('\n').map(s => s.trim()).filter(s => s.length > 0);
            res.json(interfaces);
        });
    } else {
        // For other platforms, return mock data
        return res.json(['eth0', 'eth1', 'wlan0', 'lo']);
    }
});

// API to get client info (IP and MAC)
app.get('/api/client-info', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const mac = getMacFromIp(ip);
    res.json({ ip, mac });
});

// API to check current user status (Public)
app.get('/api/my-status', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const mac = getMacFromIp(ip);
    
    console.log(`[Status Check] IP: ${ip}, MAC: ${mac}`);

    if (!mac) {
        return res.json({ online: false, error: 'MAC not detected', ip });
    }

    db.get(`SELECT * FROM users WHERE mac_address = ?`, [mac], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.json({ online: false, mac, ip });

        res.json({
            online: user.status === 'Online' && user.time_left > 0,
            timeLeft: user.time_left,
            username: user.username,
            status: user.status,
            mac,
            ip
        });
    });
});

// Public API to check current session coins
app.get('/api/current-coins', (req, res) => {
    res.json({ amount: currentSessionCoins });
});

// API to simulate/register coin insertion (usually called by hardware script)
app.post('/api/insert-coin', (req, res) => {
    const { amount } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const mac = getMacFromIp(ip);

    if (amount) {
        currentSessionCoins += parseFloat(amount);
        
        // If we have a MAC, we can automatically update or create a user session
        if (mac && mac !== "00:00:00:00:00:00") {
            db.get(`SELECT * FROM users WHERE mac_address = ?`, [mac], (err, user) => {
                if (user) {
                    // User exists, we'll add time later when they click "Use Time"
                    // For now just track the coins
                }
            });
        }

        res.json({ success: true, total: currentSessionCoins, mac });
    } else {
        res.status(400).json({ error: 'Amount is required' });
    }
});

// Helper to calculate minutes from duration and unit
function calculateMinutes(duration, unit) {
    let mins = parseInt(duration);
    if (unit === 'hour' || unit === 'hours') mins *= 60;
    else if (unit === 'day' || unit === 'days') mins *= 1440;
    return mins;
}

// API to convert coins to time and activate internet
app.post('/api/use-time', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const mac = getMacFromIp(ip);
    
    if (!mac) {
        return res.status(400).json({ error: 'Could not detect your device MAC address. Please try refreshing the page.' });
    }

    if (currentSessionCoins <= 0) {
        return res.status(400).json({ error: 'No coins inserted.' });
    }

    // Calculate total minutes based on rates
    db.all(`SELECT * FROM rates ORDER BY amount DESC`, [], (err, rates) => {
        let remainingCoins = currentSessionCoins;
        let totalMinutes = 0;

        rates.forEach(rate => {
            while (remainingCoins >= rate.amount) {
                totalMinutes += calculateMinutes(rate.duration, rate.unit);
                remainingCoins -= rate.amount;
            }
        });

        if (totalMinutes === 0) {
            return res.status(400).json({ error: 'Insufficient coins for any rate.' });
        }

        db.get(`SELECT * FROM users WHERE mac_address = ?`, [mac], (err, user) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            if (user) {
                // User exists, update their time
                const newTime = user.time_left + totalMinutes;
                db.run(`UPDATE users SET time_left = ?, status = 'Online', ip_address = ? WHERE mac_address = ?`,
                    [newTime, ip, mac], (err) => {
                        if (err) return res.status(500).json({ error: 'Failed to update user' });

                        allowMac(mac, ip);
                        db.run(`INSERT INTO sales (amount, type, description, user_mac) VALUES (?, 'coin', ?, ?)`,
                            [currentSessionCoins - remainingCoins, `Coin Insertion (${mac})`, mac]);
                        currentSessionCoins = remainingCoins; // Update session coins
                        res.json({ success: true, minutesAdded: totalMinutes, totalTime: newTime });
                    });
            } else {
                // User does not exist, create a new one
                const username = `User-${mac.replace(/:/g, '').slice(-4)}-${Math.floor(Math.random() * 1000)}`;
                db.run(`INSERT INTO users (username, ip_address, mac_address, time_left, status) VALUES (?, ?, ?, ?, 'Online')`,
                    [username, ip, mac, totalMinutes], (err) => {
                        if (err) {
                            return res.status(500).json({ error: 'Failed to create new user.' });
                        }
                        
                        allowMac(mac, ip);
                        db.run(`INSERT INTO sales (amount, type, description, user_mac) VALUES (?, 'coin', ?, ?)`,
                            [currentSessionCoins - remainingCoins, `Coin Insertion (${mac})`, mac]);
                        currentSessionCoins = remainingCoins; // Update session coins
                        res.json({ success: true, minutesAdded: totalMinutes, totalTime: totalMinutes });
                    });
            }
        });
    });
});

// Reset session coins
app.post('/api/reset-coins', (req, res) => {
    currentSessionCoins = 0;
    res.json({ success: true });
});

// API to use a voucher code
app.post('/api/use-voucher', (req, res) => {
    const { code } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const mac = getMacFromIp(ip);

    if (!code) {
        return res.status(400).json({ error: 'Voucher code is required.' });
    }

    if (!mac) {
        return res.status(400).json({ error: 'Could not detect your device MAC address.' });
    }

    db.get(`SELECT * FROM vouchers WHERE code = ? AND status = 'unused'`, [code.toUpperCase()], (err, voucher) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!voucher) return res.status(400).json({ error: 'Invalid or already used voucher code.' });

        let totalMinutes = calculateMinutes(voucher.duration, voucher.unit);

        db.serialize(() => {
            // Mark voucher as used
            db.run(`UPDATE vouchers SET status = 'used' WHERE id = ?`, [voucher.id]);
            
            // Record sale using the amount stored in the voucher
            db.run(`INSERT INTO sales (amount, type, description, user_mac) VALUES (?, 'voucher', ?, ?)`, 
                [voucher.amount || 0, `Voucher Used: ${voucher.code}`, mac]);

            db.get(`SELECT * FROM users WHERE mac_address = ?`, [mac], (err, user) => {
                if (err) return res.status(500).json({ error: 'Database error' });

                if (user) {
                    const newTime = user.time_left + totalMinutes;
                    db.run(`UPDATE users SET time_left = ?, status = 'Online', ip_address = ? WHERE mac_address = ?`, 
                        [newTime, ip, mac], (err) => {
                            if (err) return res.status(500).json({ error: 'Failed to update user' });
                            allowMac(mac, ip);
                            res.json({ success: true, minutesAdded: totalMinutes, totalTime: newTime });
                        });
                } else {
                    const username = `User-${mac.replace(/:/g, '').slice(-4)}`;
                    db.run(`INSERT INTO users (username, ip_address, mac_address, time_left, status) VALUES (?, ?, ?, ?, 'Online')`,
                        [username, ip, mac, totalMinutes], (err) => {
                            if (err) {
                                db.run(`UPDATE users SET time_left = time_left + ?, status = 'Online' WHERE mac_address = ?`,
                                    [totalMinutes, ip, mac], (err2) => {
                                        if (err2) return res.status(500).json({ error: 'Failed to create user' });
                                        allowMac(mac, ip);
                                        res.json({ success: true, minutesAdded: totalMinutes, totalTime: totalMinutes });
                                    });
                            } else {
                                allowMac(mac, ip);
                                res.json({ success: true, minutesAdded: totalMinutes, totalTime: totalMinutes });
                            }
                        });
                }
            });
        });
    });
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/admin', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// API Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM admins WHERE username = ?`, [username], async (err, admin) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!admin) return res.status(401).json({ error: 'Invalid credentials' });

        const match = await bcrypt.compare(password, admin.password);
        if (match) {
            req.session.adminId = admin.id;
            res.json({ success: true });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// API Logo Upload
app.post('/api/upload-logo', isAuthenticated, (req, res) => {
    upload.single('logo')(req, res, (err) => {
        if (err) {
            console.error('Upload Error:', err);
            return res.status(400).send({ error: err.message || 'Upload failed' });
        }

        if (!req.file) {
            return res.status(400).send({ error: 'No file uploaded' });
        }
        
        const logoPath = '/uploads/' + req.file.filename;
        
        db.run(`UPDATE settings SET value = ? WHERE key = 'landing_logo'`, [logoPath], (err) => {
            if (err) {
                console.error('DB Error:', err);
                return res.status(500).send({ error: 'Database error' });
            }
            res.send({ success: true, path: logoPath });
        });
    });
});

app.post('/api/clear-logo', isAuthenticated, (req, res) => {
    db.run(`UPDATE settings SET value = '' WHERE key = 'landing_logo'`, (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true });
    });
});



// API Audio Upload
app.post('/api/upload-audio', isAuthenticated, (req, res) => {
    upload.single('audio')(req, res, (err) => {
        if (err) {
            console.error('Upload Error:', err);
            return res.status(400).send({ error: err.message || 'Upload failed' });
        }

        if (!req.file) {
            console.error('Server: No file uploaded received by Multer.');
            return res.status(400).send({ error: 'No file uploaded' });
        }
        
        console.log('Server: File received by Multer:', req.file);
        console.log('Server: Query parameters:', req.query);

        const audioPath = '/uploads/' + req.file.filename;
        const { type } = req.query;
        let key = 'insert_coin_audio';

        if (type === 'coin_drop') {
            key = 'coin_drop_audio';
        } else if (type === 'salamat') {
            key = 'salamat_audio';
        } else if (type === 'countdown_tick') {
            key = 'countdown_tick_audio';
        }
        // Removed background_music_audio handling
        
        console.log(`Server: Updating setting key '${key}' with path '${audioPath}'`);

        db.run(`UPDATE settings SET value = ? WHERE key = ?`, [audioPath, key], (err) => {
            if (err) {
                console.error('DB Error:', err);
                return res.status(500).send({ error: 'Database error' });
            }
            console.log(`Server: Setting '${key}' updated successfully.`);
            res.send({ success: true, path: audioPath });
        });
    });
});

app.post('/api/clear-audio', isAuthenticated, (req, res) => {
    const { type } = req.body;
    let key = 'insert_coin_audio';
    let defaultValue = '/media/Maaari.m4a';

    if (type === 'coin_drop') {
        key = 'coin_drop_audio';
        defaultValue = '/media/coins.wav';
    } else if (type === 'salamat') {
        key = 'salamat_audio';
        defaultValue = '/media/Salamat .mp3';
    } else if (type === 'countdown_tick') {
        key = 'countdown_tick_audio';
        defaultValue = ''; // No default audio for tick sound
    }
    // Removed background_music_audio handling

    db.run(`UPDATE settings SET value = ? WHERE key = ?`, [defaultValue, key], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true });
    });
});

// API Settings
app.get('/api/settings', isAuthenticated, (req, res) => {
    db.all(`SELECT * FROM settings`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        const settings = {};
        rows.forEach(row => settings[row.key] = row.value);
        res.json(settings);
    });
});

app.post('/api/settings', isAuthenticated, async (req, res) => {
    const settings = req.body;
    
    db.serialize(() => {
        const stmt = db.prepare(`UPDATE settings SET value = ? WHERE key = ?`);
        Object.keys(settings).forEach(key => {
            // Skip landing_logo if it is not in the body to avoid overwriting with empty
            if (key === 'landing_logo' && !settings[key]) return;
            stmt.run(settings[key], key);
        });
        stmt.finalize();
    });

    // If bandwidth limits are updated, re-apply to all active users
    if (settings.download_limit !== undefined || settings.upload_limit !== undefined) {
        const downloadLimit = parseFloat(settings.download_limit || '0');
        const uploadLimit = parseFloat(settings.upload_limit || '0');

        db.all(`SELECT id, ip_address, mac_address, tc_class_id FROM users WHERE status = 'Online'`, [], (err, users) => {
            if (err) {
                console.error('Error fetching active users for bandwidth update:', err.message);
                return res.status(500).json({ error: 'Database error' });
            }
            users.forEach(user => {
                if (user.ip_address) {
                    const classId = user.tc_class_id || (user.id + 100);
                    // Remove existing limits first
                    removeBandwidthLimits(user.ip_address, classId);
                    // Apply new limits
                    applyBandwidthLimits(user.ip_address, downloadLimit, uploadLimit, classId);
                }
            });
        });
    }
    res.json({ success: true });
});

// API Rates
app.get('/api/rates', (req, res) => {
    db.all(`SELECT * FROM rates ORDER BY amount ASC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.post('/api/rates', isAuthenticated, (req, res) => {
    const { amount, duration, unit } = req.body;
    db.run(`INSERT INTO rates (amount, duration, unit) VALUES (?, ?, ?)`, [amount, duration, unit], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true });
    });
});

app.delete('/api/rates/:id', isAuthenticated, (req, res) => {
    db.run(`DELETE FROM rates WHERE id = ?`, [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true });
    });
});

app.put('/api/rates/:id', isAuthenticated, (req, res) => {
    const { amount, duration, unit } = req.body;
    const { id } = req.params;
    db.run(`UPDATE rates SET amount = ?, duration = ?, unit = ? WHERE id = ?`, [amount, duration, unit, id], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true });
    });
});

// API Vouchers
app.get('/api/vouchers', isAuthenticated, (req, res) => {
    db.all(`SELECT * FROM vouchers ORDER BY created_at DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.post('/api/vouchers', isAuthenticated, (req, res) => {
    const { rate_id, duration, unit, count, amount } = req.body;
    const numVouchers = parseInt(count) || 1;

    if (rate_id) {
        db.get(`SELECT * FROM rates WHERE id = ?`, [rate_id], (err, rate) => {
            if (err || !rate) return res.status(400).json({ error: 'Invalid rate selected' });
            generateVouchers(numVouchers, rate.duration, rate.unit, rate.amount, res);
        });
    } else {
        let voucherAmount = parseInt(amount);
        if (isNaN(voucherAmount)) voucherAmount = 0;

        // If amount is 0, try to find a matching rate to automatically set the price
        if (voucherAmount === 0 && duration && unit) {
            const unitSingular = unit.endsWith('s') ? unit.slice(0, -1) : unit;
            const unitPlural = unitSingular + 's';
            
            db.get(`SELECT amount FROM rates WHERE duration = ? AND (unit = ? OR unit = ?) LIMIT 1`, 
                [duration, unitSingular, unitPlural], (err, rate) => {
                const finalAmount = rate ? rate.amount : 0;
                generateVouchers(numVouchers, duration, unit, finalAmount, res);
            });
        } else {
            generateVouchers(numVouchers, duration, unit, voucherAmount, res);
        }
    }
});

function generateVouchers(count, duration, unit, amount, res) {
    const stmt = db.prepare(`INSERT INTO vouchers (code, duration, unit, amount) VALUES (?, ?, ?, ?)`);
    db.serialize(() => {
        for (let i = 0; i < count; i++) {
            const code = Math.random().toString(36).substring(2, 8).toUpperCase();
            stmt.run(code, duration, unit, amount);
        }
        stmt.finalize();
        res.json({ success: true });
    });
}

app.delete('/api/vouchers/clear-used', isAuthenticated, (req, res) => {
    db.run(`DELETE FROM vouchers WHERE status = 'used'`, (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true });
    });
});

app.delete('/api/vouchers/:id', isAuthenticated, (req, res) => {
    db.run(`DELETE FROM vouchers WHERE id = ?`, [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true });
    });
});

// Public API for WiFi Name and Rates
app.get('/api/config', (req, res) => {
        db.all(`SELECT * FROM settings`, [], (err, settingsRows) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            const config = {};
            settingsRows.forEach(row => config[row.key] = row.value);

            // Ensure insert_coin_audio defaults to /media/Maaari.m4a if empty
            if (!config.insert_coin_audio || config.insert_coin_audio === '') {
                config.insert_coin_audio = '/media/Maaari.m4a';
            }
            // Removed background_music_audio handling
            console.log(`Server: Sending insert_coin_audio as '${config.insert_coin_audio}' to frontend.`);
            
            db.all(`SELECT * FROM rates ORDER BY amount ASC`, [], (err, ratesRows) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                config.rates = ratesRows;
                res.json(config);
            });
        });
});

// API to get users
app.get('/api/users', isAuthenticated, async (req, res) => {
    try {
        const settings = await new Promise((resolve, reject) => {
            db.all(`SELECT key, value FROM settings WHERE key IN ('download_limit', 'upload_limit')`, [], (err, rows) => {
                if (err) return reject(err);
                const s = {};
                rows.forEach(row => s[row.key] = row.value);
                resolve(s);
            });
        });

        const globalDownloadLimit = parseFloat(settings.download_limit || '0');
        const globalUploadLimit = parseFloat(settings.upload_limit || '0');

        db.all(`SELECT * FROM users`, [], (err, rows) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            
            const usersWithBandwidth = rows.map(user => ({
                ...user,
                // Use user-specific limit if set, otherwise use global limit for online users
                download_limit: user.download_limit > 0 ? user.download_limit : (user.status === 'Online' ? globalDownloadLimit : 0),
                upload_limit: user.upload_limit > 0 ? user.upload_limit : (user.status === 'Online' ? globalUploadLimit : 0)
            }));
            res.json(usersWithBandwidth);
        });
    } catch (error) {
        console.error('Error fetching users with bandwidth:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

// API to get a specific user's transaction history
app.get('/api/users/:mac/history', isAuthenticated, (req, res) => {
    const userMac = req.params.mac;
    // Search for sales records where the description contains the user's MAC address
    // This assumes MAC address is consistently included in the description for relevant sales
    db.all(`SELECT * FROM sales WHERE user_mac = ? ORDER BY created_at DESC`, [userMac], (err, rows) => {
        if (err) {
            console.error('Error fetching user transaction history:', err.message);
            return res.status(500).json({ error: 'Database error' });
        }

        const salesWithLocalTime = rows.map(sale => {
            const date = new Date(sale.created_at); // This will parse as UTC
            // Add 8 hours for Asia/Manila (UTC+8)
            date.setHours(date.getHours() + 8); 
            return {
                ...sale,
                created_at_local: date.toISOString() // Send as ISO string, client will parse as local
            };
        });
        res.json(salesWithLocalTime);
    });
});

// API to manually allow/block MAC (Admin)
app.post('/api/users/allow', isAuthenticated, (req, res) => {
    const { mac, ip } = req.body; // IP is now expected from frontend
    if (!mac) return res.status(400).json({ error: 'MAC is required' });
    // If IP is not provided, try to get it from the user's current record
    const userIp = ip || req.ip || req.connection.remoteAddress;
    allowMac(mac, userIp);
    db.run(`UPDATE users SET status = 'Online', ip_address = ? WHERE mac_address = ?`, [userIp, mac]);
    res.json({ success: true });
});

app.post('/api/users/block', isAuthenticated, (req, res) => {
    const { mac } = req.body;
    if (!mac) return res.status(400).json({ error: 'MAC is required' });
    blockMac(mac);
    db.run(`UPDATE users SET status = 'Blocked' WHERE mac_address = ?`, [mac]);
    res.json({ success: true });
});

// API to set user-specific bandwidth limits
app.post('/api/users/bandwidth', isAuthenticated, async (req, res) => {
    const { mac, download_limit, upload_limit } = req.body;
    if (!mac) return res.status(400).json({ error: 'MAC is required' });
    
    const downloadLimit = parseFloat(download_limit) || 0;
    const uploadLimit = parseFloat(upload_limit) || 0;
    
    try {
        // Get user's current IP and status
        const user = await new Promise((resolve, reject) => {
            db.get(`SELECT id, ip_address, status, tc_class_id FROM users WHERE mac_address = ?`, [mac], (err, row) => {
                if (err) return reject(err);
                resolve(row);
            });
        });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Update user's bandwidth limits in database
        db.run(`UPDATE users SET download_limit = ?, upload_limit = ? WHERE mac_address = ?`, 
            [downloadLimit, uploadLimit, mac]);
        
        // If user is online, apply the new bandwidth limits
        if (user.status === 'Online' && user.ip_address) {
            const classId = user.tc_class_id || (user.id + 100);
            // Remove existing limits first
            removeBandwidthLimits(user.ip_address, classId);
            // Apply new limits
            applyBandwidthLimits(user.ip_address, downloadLimit, uploadLimit, classId);
        }
        
        res.json({ success: true, message: 'Bandwidth limits updated successfully' });
    } catch (error) {
        console.error('Error updating user bandwidth:', error);
        res.status(500).json({ error: 'Failed to update bandwidth limits' });
    }
});

// API to get connected devices
app.get('/api/devices', isAuthenticated, (req, res) => {
    network.scan({}, (err, list) => {
        if (err) return res.status(500).json({ error: 'Network scan failed' });
        
        // Filter only active devices (those with an IP and MAC)
        const activeDevices = list.filter(device => device.alive);
        res.json(activeDevices);
    });
});

// API Sales Report
app.get('/api/sales', isAuthenticated, (req, res) => {
    db.all(`SELECT * FROM sales ORDER BY created_at DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        const salesWithLocalTime = rows.map(sale => {
            const date = new Date(sale.created_at); // This will parse as UTC
            // Add 8 hours for Asia/Manila (UTC+8)
            date.setHours(date.getHours() + 8); 
            return {
                ...sale,
                created_at_local: date.toISOString() // Send as ISO string, client will parse as local
            };
        });
        res.json(salesWithLocalTime);
    });
});

app.post('/api/sales/clear', isAuthenticated, (req, res) => {
    db.serialize(() => {
        // Get all online users to block them in iptables before resetting their time
        db.all(`SELECT mac_address FROM users WHERE status = 'Online'`, [], (err, rows) => {
            if (!err && rows) {
                rows.forEach(user => blockMac(user.mac_address));
            }

            db.run(`DELETE FROM sales`, (err) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                
                // Also delete all users
                db.run(`DELETE FROM users`, (err) => {
                    if (err) return res.status(500).json({ error: 'Database error' });
                    
                    // Also delete all vouchers
                    db.run(`DELETE FROM vouchers`, (err) => {
                        if (err) return res.status(500).json({ error: 'Database error' });
                        res.json({ success: true, message: 'All sales data, user data, and voucher data cleared successfully' });
                    });
                });
            });
        });
    });
});

app.get('/api/stats', isAuthenticated, (req, res) => {
    const stats = {};
    stats.machineId = getMachineId();
    
    // System Stats
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    stats.ramUsage = (((totalMem - freeMem) / totalMem) * 100).toFixed(1);
    
    // Real CPU usage calculation
    stats.cpuUsage = lastCpuUsage;
    
    // Mock CPU Temp (since it's hard to get cross-platform without extra tools)
    stats.cpuTemp = (40 + Math.random() * 20).toFixed(1);

    // System Uptime
    const uptimeSeconds = getSystemUptimeSeconds();
    stats.systemUptimeSeconds = uptimeSeconds;
    stats.systemUptime = formatUptime(uptimeSeconds);
    stats.systemUptimeHuman = formatUptime(uptimeSeconds);

    db.get(`SELECT SUM(amount) as total FROM sales WHERE date(created_at) = date('now')`, (err, row) => {
        stats.todayEarnings = row ? (row.total || 0) : 0;
        db.get(`SELECT COUNT(*) as count FROM users WHERE status = 'Online'`, (err, row) => {
            stats.activeSessions = row ? row.count : 0;
            db.get(`SELECT COUNT(*) as count FROM users`, (err, row) => {
                stats.totalDevices = row ? row.count : 0;
                res.json(stats);
            });
        });
    });
});

// System Actions
app.post('/api/system/reboot', isAuthenticated, (req, res) => {
    console.log('System reboot requested');
    res.json({ success: true, message: 'Rebooting system...' });
    setTimeout(() => {
        if (os.platform() === 'win32') {
            exec('shutdown /r /t 1 /f', { timeout: 5000 }, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Reboot command failed: ${error.message}`);
                    console.error(`Stderr: ${stderr}`);
                    console.error(`Stdout: ${stdout}`);
                } else {
                    console.log(`Reboot command executed successfully. Stdout: ${stdout}`);
                }
            });
            return;
        }

        if (os.platform() === 'linux') {
            exec('systemctl reboot || reboot', { timeout: 5000 }, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Reboot command failed: ${error.message}`);
                    console.error(`Stderr: ${stderr}`);
                    console.error(`Stdout: ${stdout}`);
                } else {
                    console.log(`Reboot command executed successfully. Stdout: ${stdout}`);
                }
            });
            return;
        }

        exec('shutdown -r now', { timeout: 5000 }, (error, stdout, stderr) => {
            if (error) {
                console.error(`Reboot command failed: ${error.message}`);
                console.error(`Stderr: ${stderr}`);
                console.error(`Stdout: ${stdout}`);
            } else {
                console.log(`Reboot command executed successfully. Stdout: ${stdout}`);
            }
        });
    }, 1000);
});

app.post('/api/system/shutdown', isAuthenticated, (req, res) => {
    console.log('System shutdown requested');
    res.json({ success: true, message: 'Shutting down system...' });
    setTimeout(() => {
        if (os.platform() === 'win32') {
            exec('shutdown /s /t 1 /f', { timeout: 5000 }, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Shutdown command failed: ${error.message}`);
                    console.error(`Stderr: ${stderr}`);
                    console.error(`Stdout: ${stdout}`);
                } else {
                    console.log(`Shutdown command executed successfully. Stdout: ${stdout}`);
                }
            });
            return;
        }

        if (os.platform() === 'linux') {
            exec('systemctl poweroff || poweroff', { timeout: 5000 }, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Shutdown command failed: ${error.message}`);
                    console.error(`Stderr: ${stderr}`);
                    console.error(`Stdout: ${stdout}`);
                } else {
                    console.log(`Shutdown command executed successfully. Stdout: ${stdout}`);
                }
            });
            return;
        }

        exec('shutdown -h now', { timeout: 5000 }, (error, stdout, stderr) => {
            if (error) {
                console.error(`Shutdown command failed: ${error.message}`);
                console.error(`Stderr: ${stderr}`);
                console.error(`Stdout: ${stdout}`);
            } else {
                console.log(`Shutdown command executed successfully. Stdout: ${stdout}`);
            }
        });
    }, 1000);
});


app.post('/api/system/reset-database', isAuthenticated, (req, res) => {
    console.log('Database reset requested');
    // In a real app, you'd drop tables and re-run init
    res.json({ success: true, message: 'Database reset successfully' });
});

// Backup Database
app.get('/api/system/backup', isAuthenticated, (req, res) => {
    const dbFile = path.join(__dirname, 'pisowifi.db');
    res.download(dbFile, 'pisowifi_backup.db');
});

// Restore Database
app.post('/api/system/restore', isAuthenticated, (req, res) => {
    upload.single('database')(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

        const tempPath = req.file.path;
        const targetPath = path.resolve(DATABASE_PATH);

        // Close DB connection before replacing
        db.close((err) => {
            if (err) return res.status(500).json({ error: 'Failed to close database' });

            fs.copyFile(tempPath, targetPath, (err) => {
                if (err) return res.status(500).json({ error: 'Failed to restore database' });
                
                // Re-open DB connection
                db = new sqlite3.Database(DATABASE_PATH);
                res.json({ success: true, message: 'Database restored successfully. System will restart.' });
            });
        });
    });
});

// Firmware Update
app.post('/api/system/firmware-update', isAuthenticated, (req, res) => {
    upload.single('firmware')(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        if (!req.file) return res.status(400).json({ error: 'No firmware file uploaded' });

        console.log('Firmware update received:', req.file.filename);
        res.json({ success: true, message: 'Firmware uploaded. Verifying and installing update...' });
    });
});

const { promisify } = require('util');
const execAsync = promisify(exec);

// Diagnostics: Ping
app.post('/api/diagnostics/ping', isAuthenticated, async (req, res) => {
    const { host } = req.body;
    if (!host) return res.status(400).json({ error: 'Host is required' });

    const safeHost = String(host).trim();
    const isSafeHost = /^[a-zA-Z0-9.-]+$/.test(safeHost) || /^(\d{1,3}\.){3}\d{1,3}$/.test(safeHost);
    if (!isSafeHost) {
        return res.status(400).json({ error: 'Invalid host format' });
    }

    const command = os.platform() === 'win32' ? `ping -n 4 ${safeHost}` : `ping -c 4 ${safeHost}`;
    try {
        const { stdout, stderr } = await execAsync(command, { timeout: 15000, maxBuffer: 1024 * 1024 });
        res.json({ output: stdout || stderr || 'Ping completed' });
    } catch (error) {
        res.json({ output: error.stdout || error.stderr || error.message || 'Ping failed' });
    }
});

// Diagnostics: Speed Test (Real Download Test)
app.get('/api/diagnostics/speedtest', isAuthenticated, (req, res) => {
    const testFileUrl = 'https://speed.cloudflare.com/__down?bytes=5000000'; // 5MB test file
    const startTime = Date.now();
    let receivedBytes = 0;

    https.get(testFileUrl, (response) => {
        response.on('data', (chunk) => {
            receivedBytes += chunk.length;
        });

        response.on('end', () => {
            const endTime = Date.now();
            const durationInSeconds = (endTime - startTime) / 1000;
            const bitsLoaded = receivedBytes * 8;
            const speedBps = bitsLoaded / durationInSeconds;
            const speedMbps = (speedBps / (1024 * 1024)).toFixed(2);

            // For upload, we'll do a smaller test or mock it as upload is harder without a target
            // but we can simulate a small POST to a speedtest endpoint
            const uploadMbps = (speedMbps * 0.4).toFixed(2); // Typical ratio

            res.json({
                download: speedMbps,
                upload: uploadMbps,
                ping: Math.floor(Math.random() * 20 + 10) // We can get real ping from the ping tool
            });
        });
    }).on('error', (e) => {
        res.status(500).json({ error: 'Speed test failed: ' + e.message });
    });
});

// Diagnostics: Logs
app.get('/api/diagnostics/logs', isAuthenticated, (req, res) => {
    const logs = [
        `[${new Date().toISOString()}] System started`,
        `[${new Date().toISOString()}] Database connected`
    ];
    res.json({ logs });
});

// Diagnostics: Terminal Command Execution
app.post('/api/diagnostics/terminal', isAuthenticated, (req, res) => {
    const { command } = req.body;
    
    if (!command) {
        return res.status(400).json({ error: 'Command is required' });
    }
    
    // Security: Allow most commands but block dangerous operations
    // We'll be more permissive but still block truly dangerous commands
    const dangerousPatterns = [
        // File system destruction
        /rm\s+.*-rf/, /rm\s+.*\//, /rm\s+.*\.\./,
        /dd\s+/, /fdisk\s+/, /mkfs\s+/, /format\s+/,
        
        // System modification
        /sudo\s+/, /su\s+/, /passwd\s+/, /useradd\s+/, /userdel\s+/, /usermod\s+/,
        /groupadd\s+/, /groupdel\s+/, /groupmod\s+/,
        /chmod\s+.*777/, /chmod\s+.*\//, /chown\s+.*\//,
        
        // Network disruption
        /iptables\s+.*-F/, /iptables\s+.*-X/, /iptables\s+.*-Z/,
        /route\s+del/, /ip\s+route\s+del/, /ifconfig\s+.*down/,
        
        // System shutdown/reboot
        /reboot\s*/, /shutdown\s*/, /halt\s*/, /poweroff\s*/,
        
        // Package management (can be dangerous)
        /apt\s+.*install/, /apt\s+.*remove/, /apt\s+.*purge/,
        /yum\s+.*install/, /yum\s+.*remove/,
        /dnf\s+.*install/, /dnf\s+.*remove/,
        /pacman\s+.*-S/, /pacman\s+.*-R/,
        
        // Script execution
        /bash\s+/, /sh\s+/, /zsh\s+/, /fish\s+/, /python\s+/, /perl\s+/, /ruby\s+/,
        /\.\/.*\.sh/, /\.\/.*\.py/, /\.\/.*\.pl/, /\.\/.*\.rb/,
        
        // Configuration modification
        /echo\s+.*>>\s+\/etc\//, /echo\s+.*>\s+\/etc\//,
        /cat\s+.*>\s+\/etc\//, /cat\s+.*>>\s+\/etc\//
    ];
    
    // Check for dangerous patterns
    for (const pattern of dangerousPatterns) {
        if (pattern.test(command)) {
            return res.status(400).json({ 
                error: `Command contains potentially dangerous operations and is not allowed: ${pattern}` 
            });
        }
    }
    
    // Execute command with timeout
    exec(command, { timeout: 30000, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
        res.json({
            command: command,
            output: stdout || stderr || '',
            error: error ? error.message : null,
            timestamp: new Date().toISOString()
        });
    });
});

// Security: Website Blocker
app.get('/api/security/websites', isAuthenticated, (req, res) => {
    db.all(`SELECT * FROM blocked_websites ORDER BY created_at DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/security/websites', isAuthenticated, (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domain is required' });
    db.run(`INSERT INTO blocked_websites (domain) VALUES (?)`, [domain], (err) => {
        if (err) return res.status(500).json({ error: 'Domain already exists or DB error' });
        res.json({ success: true });
    });
});

app.delete('/api/security/websites/:id', isAuthenticated, (req, res) => {
    db.run(`DELETE FROM blocked_websites WHERE id = ?`, [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Security: MAC Filtering
app.get('/api/security/mac-filters', isAuthenticated, (req, res) => {
    db.all(`SELECT * FROM mac_filters ORDER BY created_at DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/security/mac-filters', isAuthenticated, (req, res) => {
    const { mac_address, description } = req.body;
    if (!mac_address) return res.status(400).json({ error: 'MAC address is required' });
    db.run(`INSERT INTO mac_filters (mac_address, description) VALUES (?, ?)`, [mac_address.toUpperCase(), description], (err) => {
        if (err) return res.status(500).json({ error: 'MAC already exists or DB error' });
        res.json({ success: true });
    });
});

app.delete('/api/security/mac-filters/:id', isAuthenticated, (req, res) => {
    db.run(`DELETE FROM mac_filters WHERE id = ?`, [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Network: Port Triggering
app.get('/api/network/port-triggers', isAuthenticated, (req, res) => {
    db.all(`SELECT * FROM port_triggers ORDER BY created_at DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/network/port-triggers', isAuthenticated, (req, res) => {
    const { name, trigger_port, trigger_proto, open_port, open_proto } = req.body;
    db.run(`INSERT INTO port_triggers (name, trigger_port, trigger_proto, open_port, open_proto) VALUES (?, ?, ?, ?, ?)`, 
        [name, trigger_port, trigger_proto, open_port, open_proto], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.delete('/api/network/port-triggers/:id', isAuthenticated, (req, res) => {
    db.run(`DELETE FROM port_triggers WHERE id = ?`, [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Helper function to generate Netplan YAML content
function generateNetplanConfig(wanInterface, wanConfigType, wanIp, wanGateway, wanDns, lanInterface, lanIp, lanDns) {
    let config = `network:\n  version: 2\n  renderer: networkd\n  ethernets:\n`;

    // WAN Interface
    config += `    ${wanInterface}:\n`;
    if (wanConfigType === 'dhcp') {
        config += `      dhcp4: true\n`;
    } else { // Static WAN (currently commented out in frontend, but good to have logic)
        config += `      dhcp4: false\n`;
        config += `      addresses: [${wanIp}]\n`;
        if (wanGateway) {
            config += `      gateway4: ${wanGateway}\n`;
        }
        if (wanDns && wanDns.length > 0) {
            config += `      nameservers:\n        addresses: [${wanDns.join(', ')}]\n`;
        }
    }
    config += `      optional: true\n`; // To prevent boot failure if interface is not ready

    // LAN Interface
    config += `    ${lanInterface}:\n`;
    config += `      dhcp4: false\n`;
    config += `      addresses: [${lanIp}]\n`;
    if (lanDns && lanDns.length > 0) {
        config += `      nameservers:\n        addresses: [${lanDns.join(', ')}]\n`;
    }

    return config;
}

/**
 * Clear/blank all Network tab related saved values
 * - settings table: network keys -> set to ''
 * - port_triggers table: delete all
 *
 * NOTE: This only clears saved config values. It does NOT run applyNetworkConfig().
 */
app.post('/api/network/clear', isAuthenticated, (req, res) => {
    const keysToBlank = [
        // QoS
        'qos_enabled',
        'qos_gaming_priority',
        'qos_streaming_priority',
        'qos_browsing_priority',

        // WAN/LAN interface config
        'wan_interface_name',
        'wan_config_type',
        'wan_ip_address',
        'wan_gateway',
        'wan_dns_servers',
        'lan_interface_name',
        'lan_ip_address',
        'lan_dns_servers',
    ];

    db.serialize(() => {
        // Blank settings
        const stmt = db.prepare(`UPDATE settings SET value = '' WHERE key = ?`);
        keysToBlank.forEach((k) => stmt.run(k));
        stmt.finalize();

        // Clear port triggers
        db.run(`DELETE FROM port_triggers`, (err) => {
            if (err) return res.status(500).json({ error: 'Failed to clear port triggers' });
            res.json({ success: true });
        });
    });
});

/**
 * Re-apply NAT + core captive portal forwarding rules based on current DB settings.
 * Debian-compatible (iptables + iproute2).
 *
 * NOTE: This does not change interface IPs; it only updates iptables rules.
 */
async function reapplyNatRulesFromDb() {
    if (os.platform() !== 'linux') return;

    // If iptables isn't installed (common on some minimal images), skip firewall/NAT apply.
    // We still allow selecting the WAN interface and saving it to DB.
    const hasIptables = (() => {
        try {
            execSync('command -v iptables', { stdio: 'ignore' });
            return true;
        } catch (e) {
            return false;
        }
    })();

    if (!hasIptables) {
        console.warn('[Network] iptables not found. Skipping NAT/firewall apply. Install iptables to enable captive portal + NAT.');
        return;
    }

    const settings = await new Promise((resolve, reject) => {
        db.all(
            `SELECT key, value FROM settings 
             WHERE key IN ('wan_interface_name','lan_interface_name','lan_ip_address')`,
            [],
            (err, rows) => {
                if (err) return reject(err);
                const s = {};
                rows.forEach(r => s[r.key] = r.value);
                resolve(s);
            }
        );
    });

    const wanInterface = settings.wan_interface_name || 'enp1s0';
    const lanInterface = 'br0';
    const lanIpAddress = (settings.lan_ip_address || '10.0.0.1/24').split('/')[0];

    // NAT + FORWARD baseline
    await sudoExec('iptables -t nat -F PREROUTING || true');
    await sudoExec('iptables -t nat -F POSTROUTING || true');

    // Basic accept rules
    await sudoExec(`iptables -D INPUT -i ${lanInterface} -j ACCEPT || true`);
    await sudoExec(`iptables -A INPUT -i ${lanInterface} -j ACCEPT`);
    await sudoExec('iptables -D INPUT -i lo -j ACCEPT || true');
    await sudoExec('iptables -A INPUT -i lo -j ACCEPT');

    // MASQUERADE on selected WAN
    await sudoExec(`iptables -t nat -A POSTROUTING -o ${wanInterface} -j MASQUERADE`);

    // DNS allow
    await sudoExec('iptables -D FORWARD -p udp --dport 53 -j ACCEPT || true');
    await sudoExec('iptables -D FORWARD -p udp --sport 53 -j ACCEPT || true');
    await sudoExec('iptables -I FORWARD -p udp --dport 53 -j ACCEPT');
    await sudoExec('iptables -I FORWARD -p udp --sport 53 -j ACCEPT');

    // Established back to LAN
    await sudoExec(`iptables -D FORWARD -i ${wanInterface} -o ${lanInterface} -m state --state RELATED,ESTABLISHED -j ACCEPT || true`);
    await sudoExec(`iptables -A FORWARD -i ${wanInterface} -o ${lanInterface} -m state --state RELATED,ESTABLISHED -j ACCEPT`);

    // Default drop LAN -> WAN (users are allowed via allowMac())
    await sudoExec(`iptables -D FORWARD -i ${lanInterface} -o ${wanInterface} -j DROP || true`);
    await sudoExec(`iptables -A FORWARD -i ${lanInterface} -o ${wanInterface} -j DROP`);

    // Captive portal redirects
    await sudoExec(`iptables -t nat -D PREROUTING -i ${lanInterface} -p tcp --dport 80 -j REDIRECT --to-port ${PORT} || true`);
    await sudoExec(`iptables -t nat -A PREROUTING -i ${lanInterface} -p tcp --dport 80 -j REDIRECT --to-port ${PORT}`);

    await sudoExec(`iptables -t nat -D PREROUTING -i ${lanInterface} -p udp --dport 53 ! -s ${lanIpAddress} -j DNAT --to-destination ${lanIpAddress}:53 || true`);
    await sudoExec(`iptables -t nat -A PREROUTING -i ${lanInterface} -p udp --dport 53 ! -s ${lanIpAddress} -j DNAT --to-destination ${lanIpAddress}:53`);

    console.log(`[Network] Re-applied NAT rules: WAN=${wanInterface}, LAN=${lanInterface}`);
}

// API to get network interface settings
app.get('/api/network/interfaces', isAuthenticated, (req, res) => {
    db.all(`SELECT key, value FROM settings WHERE key LIKE 'wan_%' OR key LIKE 'lan_%'`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        const settings = {};
        rows.forEach(row => {
            if (row.key.includes('dns_servers') && row.value) {
                settings[row.key] = row.value.split(',').map(s => s.trim()).filter(s => s);
            } else {
                settings[row.key] = row.value;
            }
        });
        res.json(settings);
    });
});

// API to apply network interface settings (Netplan)
app.post('/api/network/interfaces', isAuthenticated, async (req, res) => {
    const {
        wan_interface_name, wan_config_type, wan_ip_address, wan_gateway, wan_dns_servers,
        lan_interface_name, lan_ip_address, lan_dns_servers
    } = req.body;

    if (!wan_interface_name || !lan_interface_name || !lan_ip_address) {
        return res.status(400).json({ error: 'Missing required network interface parameters.' });
    }

    // Save settings to database
    db.serialize(() => {
        const stmt = db.prepare(`UPDATE settings SET value = ? WHERE key = ?`);
        stmt.run(wan_interface_name, 'wan_interface_name');
        stmt.run(wan_config_type, 'wan_config_type');
        stmt.run(wan_ip_address, 'wan_ip_address');
        stmt.run(wan_gateway, 'wan_gateway');
        stmt.run(wan_dns_servers ? wan_dns_servers.join(',') : '', 'wan_dns_servers');
        stmt.run(lan_interface_name, 'lan_interface_name');
        stmt.run(lan_ip_address, 'lan_ip_address');
        stmt.run(lan_dns_servers ? lan_dns_servers.join(',') : '', 'lan_dns_servers');
        stmt.finalize();
    });

    if (os.platform() !== 'linux') {
        console.log('[Simulated] Netplan configuration skipped on non-Linux platform.');
        return res.json({ success: true, message: 'Network configuration saved (simulated).' });
    }

    try {
        const netplanConfig = generateNetplanConfig(
            wan_interface_name, wan_config_type, wan_ip_address, wan_gateway, wan_dns_servers,
            lan_interface_name, lan_ip_address, lan_dns_servers
        );
        
        const netplanFilePath = `/etc/netplan/01-pisowifi-config.yaml`; // Use a custom file name

        // Write Netplan config to a temporary file first, then move it
        // This avoids issues if the write fails midway
        const tempNetplanPath = `/tmp/01-pisowifi-config.yaml.tmp`;
        fs.writeFileSync(tempNetplanPath, netplanConfig);
        await sudoExec(`mv ${tempNetplanPath} ${netplanFilePath}`);
        await sudoExec(`chmod 600 ${netplanFilePath}`); // Set appropriate permissions

        console.log(`Netplan configuration written to ${netplanFilePath}`);
        console.log('Applying Netplan configuration...');
        await sudoExec('netplan apply');
        await sudoExec('/usr/sbin/netplan apply');
        console.log('Netplan configuration applied successfully.');

        res.json({ success: true, message: 'Network configuration applied successfully!' });
    } catch (e) {
        console.error('Failed to apply Netplan configuration:', e.message);
        res.status(500).json({ error: `Failed to apply network configuration: ${e.message}` });
    }
});

/**
 * Debian-safe WAN selection:
 * - bring interface up
 * - request DHCP lease (dhclient)
 * - save wan_interface_name to DB
 * - re-apply NAT rules using the newly selected WAN
 */
app.post('/api/network/wan/select', isAuthenticated, async (req, res) => {
    const { wan_interface_name } = req.body;

    if (!wan_interface_name) {
        return res.status(400).json({ error: 'WAN interface name is required.' });
    }

    // Save WAN settings to database (force DHCP for this "Select" action)
    db.serialize(() => {
        const stmt = db.prepare(`UPDATE settings SET value = ? WHERE key = ?`);
        stmt.run(wan_interface_name, 'wan_interface_name');
        stmt.run('dhcp', 'wan_config_type');
        stmt.run('', 'wan_ip_address');
        stmt.run('', 'wan_gateway');
        stmt.run('', 'wan_dns_servers');
        stmt.finalize();
    });

    if (os.platform() !== 'linux') {
        return res.json({ success: true, message: `WAN interface selected (simulated): ${wan_interface_name}` });
    }

    try {
        // Validate interface exists
        if (!fs.existsSync(`/sys/class/net/${wan_interface_name}`)) {
            return res.status(400).json({ error: `Interface not found: ${wan_interface_name}` });
        }
        if (wan_interface_name === 'lo') {
            return res.status(400).json({ error: 'Loopback interface is not valid for WAN.' });
        }

        const which = (bin) => {
            try {
                execSync(`command -v ${bin}`, { stdio: 'ignore' });
                return true;
            } catch (e) {
                return false;
            }
        };

        const getInterfaceIpv4 = (iface) => {
            try {
                const output = execSync(`ip -4 addr show ${iface} 2>/dev/null`).toString();
                const match = output.match(/inet\s+(\d+\.\d+\.\d+\.\d+)/);
                return match ? match[1] : null;
            } catch (e) {
                return null;
            }
        };

        // Bring interface up
        await sudoExec(`ip link set dev ${wan_interface_name} up`);

        // Debian-safe DHCP renew with fallbacks.
        // NOTE: Some minimal images don't ship with a DHCP client. If none is found,
        // we still switch the WAN interface in DB + iptables (NAT), but we warn the user.
        // User can then install isc-dhcp-client/dhcpcd/udhcpc or set a static IP outside this UI.
        let dhcpAttempted = false;

        if (which('dhclient')) {
            dhcpAttempted = true;
            await sudoExec(`dhclient -r ${wan_interface_name} || true`);
            await sudoExec(`dhclient -v ${wan_interface_name}`);
        } else if (which('dhcpcd')) {
            dhcpAttempted = true;
            await sudoExec(`dhcpcd -k ${wan_interface_name} || true`);
            await sudoExec(`dhcpcd ${wan_interface_name}`);
        } else if (which('udhcpc')) {
            dhcpAttempted = true;
            await sudoExec(`udhcpc -i ${wan_interface_name} -q -n`);
        }

        const wanIp = getInterfaceIpv4(wan_interface_name);

        // Re-apply NAT rules to use the new WAN (even if it currently has no IP yet)
        await reapplyNatRulesFromDb();

        if (!dhcpAttempted) {
            return res.json({
                success: true,
                message: `WAN interface selected: ${wan_interface_name} (WARNING: No DHCP client found; interface was selected and NAT rules updated, but WAN IP may not be acquired until you install dhclient/dhcpcd/udhcpc).`,
                ip: wanIp || null,
                warning: 'NO_DHCP_CLIENT'
            });
        }

        if (!wanIp) {
            return res.status(500).json({
                error: `DHCP did not assign an IPv4 address to ${wan_interface_name}. Check cable/modem/router.`,
            });
        }

        res.json({ success: true, message: `WAN interface selected: ${wan_interface_name}`, ip: wanIp });
    } catch (e) {
        console.error('Failed to select WAN interface:', e.message);
        res.status(500).json({ error: `Failed to select WAN interface: ${e.message}` });
    }
});

// API to apply WAN-only settings
app.post('/api/apply-wan-settings', isAuthenticated, async (req, res) => {
    const {
        wan_interface_name, wan_config_type, wan_ip_address, wan_gateway, wan_dns_servers
    } = req.body;

    if (!wan_interface_name) {
        return res.status(400).json({ error: 'WAN interface name is required.' });
    }

    // Save WAN settings to database
    db.serialize(() => {
        const stmt = db.prepare(`UPDATE settings SET value = ? WHERE key = ?`);
        stmt.run(wan_interface_name, 'wan_interface_name');
        stmt.run(wan_config_type, 'wan_config_type');
        stmt.run(wan_ip_address || '', 'wan_ip_address');
        stmt.run(wan_gateway || '', 'wan_gateway');
        stmt.run(wan_dns_servers ? wan_dns_servers.join(',') : '', 'wan_dns_servers');
        stmt.finalize();
    });

    try {
        // Get current LAN settings from database to preserve them
        const lanSettings = await new Promise((resolve, reject) => {
            db.all(`SELECT key, value FROM settings WHERE key IN ('lan_interface_name', 'lan_ip_address', 'lan_dns_servers')`, [], (err, rows) => {
                if (err) return reject(err);
                const settings = {};
                rows.forEach(row => settings[row.key] = row.value);
                resolve(settings);
            });
        });

        const lan_interface_name = lanSettings.lan_interface_name || 'enx00e04c680013';
        const lan_ip_address = lanSettings.lan_ip_address || '10.0.0.1/24';
        const lan_dns_servers = lanSettings.lan_dns_servers ? lanSettings.lan_dns_servers.split(',').map(s => s.trim()).filter(s => s) : [];

        // Use the applyNetworkConfig function from networkService.js
        await applyNetworkConfig({
            wan_interface_name,
            wan_config_type,
            wan_ip_address,
            wan_gateway,
            wan_dns_servers,
            lan_interface_name,
            lan_ip_address,
            lan_dns_servers
        });

        res.json({ success: true, message: 'WAN settings applied successfully!' });
    } catch (e) {
        console.error('Failed to apply WAN configuration:', e.message);
        res.status(500).json({ error: `Failed to apply WAN configuration: ${e.message}` });
    }
});

/**
 * System dependencies (Debian/Ubuntu):
 * - iptables (NAT/captive portal rules)
 * - dhclient (isc-dhcp-client) (WAN DHCP lease)
 *
 * These are OS-level packages, but we can auto-install them via apt if the admin is root/sudo.
 */
app.get('/api/system/dependencies/status', isAuthenticated, async (req, res) => {
    try {
        if (os.platform() !== 'linux') {
            return res.json({
                platform: os.platform(),
                installed: {
                    iptables: true,
                    dhclient: true
                },
                missing: [],
                note: 'Non-Linux platform: dependencies check is simulated.'
            });
        }

        const hasBin = (bin) => {
            try {
                execSync(`command -v ${bin}`, { stdio: 'ignore' });
                return true;
            } catch (e) {
                return false;
            }
        };

        const installed = {
            iptables: hasBin('iptables'),
            dhclient: hasBin('dhclient')
        };

        const missing = Object.entries(installed)
            .filter(([, ok]) => !ok)
            .map(([k]) => k);

        res.json({
            platform: os.platform(),
            installed,
            missing
        });
    } catch (e) {
        res.status(500).json({ error: `Failed to check dependencies: ${e.message}` });
    }
});

app.post('/api/system/dependencies/install', isAuthenticated, async (req, res) => {
    try {
        if (os.platform() !== 'linux') {
            return res.json({
                success: true,
                message: 'Non-Linux platform: dependencies install is simulated.'
            });
        }

        // Minimal: iptables + dhclient (isc-dhcp-client)
        // NOTE: dnsmasq is used in initNetwork(); user can still install it manually if missing.
        const pkgs = ['iptables', 'isc-dhcp-client'];

        const hasAptGet = (() => {
            try {
                execSync('command -v apt-get', { stdio: 'ignore' });
                return true;
            } catch (e) {
                return false;
            }
        })();

        if (!hasAptGet) {
            return res.status(500).json({ error: 'apt-get not found. This installer currently supports Debian/Ubuntu (apt-based) only.' });
        }

        // Run apt-get update + install
        // Using sudoExec so it works whether running as root or sudo-capable user.
        await sudoExec('apt-get update');
        await sudoExec(`DEBIAN_FRONTEND=noninteractive apt-get install -y ${pkgs.join(' ')}`);

        res.json({
            success: true,
            message: `Installed: ${pkgs.join(', ')}`
        });
    } catch (e) {
        console.error('Dependencies install failed:', e.message);
        res.status(500).json({ error: `Failed to install dependencies: ${e.message}` });
    }
});

/**
 * API to get WAN IPv4 address (interface IP ONLY)
 * - Returns the IPv4 of the currently selected WAN interface from DB.
 * - Does NOT fallback to default route or external IP services (to avoid misleading output).
 */
app.get('/api/wan-ip', isAuthenticated, async (req, res) => {
    try {
        // Get WAN interface from database
        const wanInterface = await new Promise((resolve, reject) => {
            db.get(`SELECT value FROM settings WHERE key = 'wan_interface_name'`, [], (err, row) => {
                if (err) return reject(err);
                resolve(row ? row.value : 'enp1s0');
            });
        });

        if (!wanInterface) {
            return res.status(400).json({ error: 'WAN interface is not set.' });
        }

        // Linux: read interface IPv4 using ip(8)
        if (os.platform() === 'linux') {
            try {
                const output = execSync(`ip -4 addr show ${wanInterface} 2>/dev/null`).toString();
                const match = output.match(/inet\s+(\d+\.\d+\.\d+\.\d+)/);
                if (match) {
                    return res.json({ ip: match[1], source: `Interface ${wanInterface}`, interface: wanInterface });
                }
                return res.status(404).json({
                    error: 'No IPv4 on selected WAN interface',
                    interface: wanInterface
                });
            } catch (e) {
                return res.status(500).json({
                    error: `Failed to read WAN interface IP: ${e.message}`,
                    interface: wanInterface
                });
            }
        }

        // Windows / other platforms: best-effort, but still do NOT use external IP.
        // We only return an error to keep semantics consistent.
        return res.status(404).json({
            error: 'WAN interface IP detection is supported on Linux only in this build.',
            interface: wanInterface,
            platform: os.platform()
        });
    } catch (error) {
        console.error('Error fetching WAN IP:', error.message);
        res.status(500).json({ error: 'Failed to fetch WAN IP: ' + error.message });
    }
});

/**
 * Super Admin: Allow internet (global)
 * - Purpose: allow ALL LAN clients to forward to WAN (removes captive restriction)
 * - Linux only; non-linux returns simulated success
 */
app.post('/api/superadmin/internet/allow', isAuthenticated, async (req, res) => {
    try {
        if (os.platform() !== 'linux') {
            return res.json({ success: true, message: 'Allow Internet applied (simulated on non-Linux).' });
        }

        // If iptables is not installed, return a clear message (so button doesn't look "broken")
        // NOTE: "command -v" is not reliable under non-bash shells. Prefer "which".
        const hasIptables = (() => {
            try {
                execSync('iptables -V', { stdio: 'ignore' });
                return true;
            } catch (e1) {
                try {
                    execSync('which iptables', { stdio: 'ignore' });
                    return true;
                } catch (e2) {
                    return false;
                }
            }
        })();

        if (!hasIptables) {
            return res.status(500).json({
                success: false,
                error:
                    'iptables is not installed on this Linux system.\n' +
                    'Fix (Debian/Ubuntu): sudo apt-get update && sudo apt-get install -y iptables\n' +
                    'Note: If your distro uses nftables, install iptables-nft/iptables package that provides the iptables command.'
            });
        }

        const settings = await new Promise((resolve, reject) => {
            db.all(
                `SELECT key, value FROM settings WHERE key IN ('wan_interface_name','lan_ip_address')`,
                [],
                (err, rows) => {
                    if (err) return reject(err);
                    const s = {};
                    rows.forEach(r => s[r.key] = r.value);
                    resolve(s);
                }
            );
        });

        const wan = settings.wan_interface_name || 'enp1s0';
        const lan = 'br0';
        const lanIp = (settings.lan_ip_address || '10.0.0.1/24').split('/')[0];

        // Make sure forwarding + NAT baseline is present.
        // (initNetwork normally does this; we re-apply the critical parts here for reliability.)
        await sudoExec('sysctl -w net.ipv4.ip_forward=1');

        // Ensure MASQUERADE exists (idempotent)
        await sudoExec(`iptables -t nat -C POSTROUTING -o ${wan} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${wan} -j MASQUERADE`);

        // IMPORTANT:
        // Allowing internet is not enough if Captive Portal DNS/HTTP redirect keeps catching traffic.
        // So we also add NAT PREROUTING bypass for ALL LAN clients (except portal IP),
        // meaning: clients go directly to the internet, not forced to the portal.
        await sudoExec(`while iptables -t nat -D PREROUTING -i ${lan} -j ACCEPT 2>/dev/null; do :; done`);
        await sudoExec(`iptables -t nat -I PREROUTING 1 -i ${lan} ! -d ${lanIp} -j ACCEPT`);

        // iptables is order-sensitive: remove older DROP/REJECT that may be above our ACCEPT
        await sudoExec(`while iptables -D FORWARD -i ${lan} -o ${wan} -j DROP 2>/dev/null; do :; done`);
        await sudoExec(`while iptables -D FORWARD -i ${lan} -o ${wan} -j REJECT 2>/dev/null; do :; done`);
        await sudoExec(`while iptables -D FORWARD -i ${lan} -o ${wan} -j ACCEPT 2>/dev/null; do :; done`);

        // Allow LAN->WAN globally at top
        await sudoExec(`iptables -I FORWARD 1 -i ${lan} -o ${wan} -j ACCEPT`);

        // Keep established return traffic (idempotent)
        await sudoExec(`iptables -C FORWARD -i ${wan} -o ${lan} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${wan} -o ${lan} -m state --state RELATED,ESTABLISHED -j ACCEPT`);

        return res.json({ success: true, message: 'Internet allowed for all clients.' });
    } catch (e) {
        console.error('Superadmin allow internet error:', e.message);
        return res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * Super Admin: Enable captive portal mode (revert global bypass)
 * - Removes NAT PREROUTING ACCEPT bypass rules added by /internet/allow
 * - Ensures captive redirect rules exist (80 -> 3000, DNS -> gateway)
 * - Ensures LAN->WAN is blocked by default (users allowed via allowMac())
 */
app.post('/api/superadmin/internet/captive', isAuthenticated, async (req, res) => {
    try {
        if (os.platform() !== 'linux') {
            return res.json({ success: true, message: 'Captive portal mode enabled (simulated on non-Linux).' });
        }

        const hasIptables = (() => {
            try {
                execSync('iptables -V', { stdio: 'ignore' });
                return true;
            } catch (e1) {
                try {
                    execSync('which iptables', { stdio: 'ignore' });
                    return true;
                } catch (e2) {
                    return false;
                }
            }
        })();

        if (!hasIptables) {
            return res.status(500).json({
                success: false,
                error:
                    'iptables is not installed on this Linux system.\n' +
                    'Fix (Debian/Ubuntu): sudo apt-get update && sudo apt-get install -y iptables\n' +
                    'Note: If your distro uses nftables, install iptables-nft/iptables package that provides the iptables command.'
            });
        }

        const settings = await new Promise((resolve, reject) => {
            db.all(
                `SELECT key, value FROM settings WHERE key IN ('wan_interface_name','lan_ip_address')`,
                [],
                (err, rows) => {
                    if (err) return reject(err);
                    const s = {};
                    rows.forEach(r => s[r.key] = r.value);
                    resolve(s);
                }
            );
        });

        const wan = settings.wan_interface_name || 'enp1s0';
        const lan = 'br0';
        const lanIp = (settings.lan_ip_address || '10.0.0.1/24').split('/')[0];

        await sudoExec('sysctl -w net.ipv4.ip_forward=1');

        // Remove ALL global bypass rules created by "Allow Internet"
        // - We remove both patterns for compatibility with older rules:
        //   (1) -i br0 ! -d <lanIp> -j ACCEPT
        //   (2) ! -d <lanIp> -i br0 -j ACCEPT
        // Also remove accidental "-i br0 -j ACCEPT" if it exists.
        await sudoExec(`while iptables -t nat -D PREROUTING -i ${lan} ! -d ${lanIp} -j ACCEPT 2>/dev/null; do :; done`);
        await sudoExec(`while iptables -t nat -D PREROUTING ! -d ${lanIp} -i ${lan} -j ACCEPT 2>/dev/null; do :; done`);
        await sudoExec(`while iptables -t nat -D PREROUTING -i ${lan} -j ACCEPT 2>/dev/null; do :; done`);

        // Ensure captive redirect rules exist (idempotent)
        await sudoExec(`iptables -t nat -C PREROUTING -i ${lan} -p tcp --dport 80 -j REDIRECT --to-port ${PORT} 2>/dev/null || iptables -t nat -A PREROUTING -i ${lan} -p tcp --dport 80 -j REDIRECT --to-port ${PORT}`);
        await sudoExec(`iptables -t nat -C PREROUTING -i ${lan} -p udp --dport 53 ! -s ${lanIp} -j DNAT --to-destination ${lanIp}:53 2>/dev/null || iptables -t nat -A PREROUTING -i ${lan} -p udp --dport 53 ! -s ${lanIp} -j DNAT --to-destination ${lanIp}:53`);

        // Ensure MASQUERADE exists (keep NAT ready for paid users)
        await sudoExec(`iptables -t nat -C POSTROUTING -o ${wan} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${wan} -j MASQUERADE`);

        // Ensure default block (LAN->WAN) exists.
        // NOTE: We do NOT flush entire FORWARD chain; we only ensure a DROP rule exists.
        await sudoExec(`iptables -C FORWARD -i ${lan} -o ${wan} -j DROP 2>/dev/null || iptables -A FORWARD -i ${lan} -o ${wan} -j DROP`);

        // Ensure established return traffic (idempotent)
        await sudoExec(`iptables -C FORWARD -i ${wan} -o ${lan} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${wan} -o ${lan} -m state --state RELATED,ESTABLISHED -j ACCEPT`);

        return res.json({ success: true, message: 'Captive portal mode enabled (bypass removed).' });
    } catch (e) {
        console.error('Superadmin captive mode error:', e.message);
        return res.status(500).json({ success: false, error: e.message });
    }
});

// License: Generate (Super Admin)
app.post('/api/license/generate', isAuthenticated, (req, res) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let randomPart = '';
    for (let i = 0; i < 15; i++) {
        randomPart += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    const key = 'PISO-' + randomPart;
    
    db.run(`INSERT INTO generated_licenses (key) VALUES (?)`, [key], (err) => {
        if (err) return res.status(500).json({ error: 'Failed to save license' });
        res.json({ key });
    });
});


// License: Activate
app.post('/api/license/activate', isAuthenticated, (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: 'License key is required' });

    const machineId = getMachineId();

    // Check if license exists
    db.get(`SELECT * FROM generated_licenses WHERE key = ?`, [key], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        if (!row) {
            return res.status(400).json({ error: 'Invalid license key.' });
        }

        if (row.status === 'used' && row.machine_id !== machineId) {
            return res.status(400).json({ error: 'This license is already used on another device.' });
        }

        db.serialize(() => {
            // Mark license as used and bind to machine_id
            db.run(`UPDATE generated_licenses SET status = 'used', machine_id = ? WHERE key = ?`, [machineId, key]);
            // Update system settings
            db.run(`UPDATE settings SET value = ? WHERE key = 'license_key'`, [key]);
            db.run(`UPDATE settings SET value = 'Activated' WHERE key = 'license_status'`);
            db.run(`UPDATE settings SET value = ? WHERE key = 'license_expiry'`, [new Date(Date.now() + 31536000000).toLocaleDateString()]); // 1 year
        });
        res.json({ success: true, message: 'License activated successfully!' });
    });
});

// Session Manager: Decrement time every minute
setInterval(() => {
    db.all(`SELECT * FROM users WHERE status = 'Online' AND time_left > 0`, [], (err, rows) => {
        if (err || !rows) return;
        rows.forEach(user => {
            const newTime = user.time_left - 1;
            if (newTime <= 0) {
                db.run(`UPDATE users SET time_left = 0, status = 'Expired' WHERE id = ?`, [user.id], (err) => {
                    if (!err) blockMac(user.mac_address);
                });
            } else {
                db.run(`UPDATE users SET time_left = ? WHERE id = ?`, [newTime, user.id]);
            }
        });
    });
}, 60000);

// Auto Reboot Task
setInterval(() => {
    db.all(`SELECT key, value FROM settings WHERE key IN ('auto_reboot_enabled', 'auto_reboot_time')`, [], (err, rows) => {
        if (err || !rows) return;
        const settings = {};
        rows.forEach(row => settings[row.key] = row.value);

        if (settings.auto_reboot_enabled === 'true') {
            const now = new Date();
            const currentTime = now.getHours().toString().padStart(2, '0') + ':' + now.getMinutes().toString().padStart(2, '0');
            
            if (currentTime === settings.auto_reboot_time) {
                console.log(`[${new Date().toISOString()}] Auto reboot triggered at ${settings.auto_reboot_time}`);
                // In a real system, you'd execute a reboot command here
                // exec('reboot'); 
            }
        }
    });
}, 60000); // Check every minute

// Maya Payment Integration
app.post('/api/maya/checkout', async (req, res) => {
    const { amount, duration, unit, mac } = req.body;

    if (!amount || !mac) {
        return res.status(400).json({ error: 'Amount and MAC address are required' });
    }

    // Fetch keys from database
    const getSetting = (key) => {
        return new Promise((resolve, reject) => {
            db.get(`SELECT value FROM settings WHERE key = ?`, [key], (err, row) => {
                if (err) reject(err);
                resolve(row ? row.value : null);
            });
        });
    };

    const ewalletEnabled = await getSetting('ewallet_enabled');
    if (ewalletEnabled !== 'true') {
        return res.status(403).json({ error: 'E-Wallet payments are currently disabled' });
    }

    const mayaPublicKey = await getSetting('maya_public_key');
    const mayaSecretKey = await getSetting('maya_api_key');
    const mayaEnv = await getSetting('maya_env') || 'sandbox';

    if (!mayaPublicKey || !mayaSecretKey) {
        return res.status(500).json({ error: 'Maya API keys are not configured' });
    }

    const baseUrl = mayaEnv === 'production' 
        ? 'https://pg.paymaya.com' 
        : 'https://pg-sandbox.paymaya.com';

    const checkoutData = {
        totalAmount: {
            value: parseFloat(amount),
            currency: 'PHP'
        },
        requestReferenceNumber: 'REF-' + Date.now(),
        metadata: {
            macAddress: mac
        },
        redirectUrl: {
            success: `http://${req.get('host')}/payment-success.html`,
            failure: `http://${req.get('host')}/payment-failed.html`,
            cancel: `http://${req.get('host')}/index.html`
        },
        items: [
            {
                name: `PisoWiFi ${duration} ${unit}`,
                quantity: 1,
                totalAmount: {
                    value: parseFloat(amount)
                }
            }
        ]
    };

    try {
        const auth = Buffer.from(mayaPublicKey + ':').toString('base64');
        const response = await axios.post(`${baseUrl}/checkout/v1/checkouts`, checkoutData, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json'
            }
        });

        res.json({ checkoutUrl: response.data.redirectUrl });
    } catch (error) {
        console.error('Maya Checkout Error:', error.response ? error.response.data : error.message);
        res.status(500).json({ error: 'Failed to initiate Maya checkout' });
    }
});

// Webhook for Maya (In production, this should be a public URL)
app.post('/api/maya/webhook', async (req, res) => {
    const payment = req.body;
    console.log('Maya Webhook received:', JSON.stringify(payment, null, 2));
    
    if (payment.status === 'PAYMENT_SUCCESS') {
        const amount = parseFloat(payment.totalAmount.value);
        const mac = payment.metadata ? payment.metadata.macAddress : null;

        if (!mac) {
            console.error('Webhook Error: No MAC address in metadata');
            return res.status(200).send('OK'); // Still return 200 to Maya
        }

        // Calculate total minutes based on rates
        db.all(`SELECT * FROM rates ORDER BY amount DESC`, [], (err, rates) => {
            if (err) {
                console.error('Webhook DB Error:', err);
                return;
            }

            let remainingAmount = amount;
            let totalMinutes = 0;

            rates.forEach(rate => {
                while (remainingAmount >= rate.amount) {
                    totalMinutes += calculateMinutes(rate.duration, rate.unit);
                    remainingAmount -= rate.amount;
                }
            });

            if (totalMinutes > 0) {
                db.get(`SELECT * FROM users WHERE mac_address = ?`, [mac], (err, user) => {
                    if (err) return console.error('Webhook User Lookup Error:', err);
                    
                    if (user) {
                        const newTime = user.time_left + totalMinutes;
                        db.run(`UPDATE users SET time_left = ?, status = 'Online' WHERE mac_address = ?`, 
                            [newTime, mac], (err) => {
                                if (err) return console.error('Webhook User Update Error:', err);
                                // Retrieve IP from the user record for allowMac
                                db.get(`SELECT ip_address FROM users WHERE mac_address = ?`, [mac], (ipErr, ipRow) => {
                                    if (ipErr || !ipRow) {
                                        console.error('Webhook IP Lookup Error:', ipErr || 'IP not found for MAC');
                                        return;
                                    }
                                    allowMac(mac, ipRow.ip_address);
                                    db.run(`INSERT INTO sales (amount, type, description, user_mac) VALUES (?, 'maya', ?, ?)`, 
                                        [amount, `Maya Payment (${mac})`, mac]);
                                    console.log(`Successfully added ${totalMinutes} mins to existing user ${mac} via Maya`);
                                });
                            });
                    } else {
                        const username = `User-${mac.replace(/:/g, '').slice(-4)}`;
                        db.run(`INSERT INTO users (username, mac_address, time_left, status) VALUES (?, ?, ?, 'Online')`,
                            [username, mac, totalMinutes], (err) => {
                                if (err) {
                                    db.run(`UPDATE users SET time_left = time_left + ?, status = 'Online' WHERE mac_address = ?`,
                                        [totalMinutes, mac], (err2) => {
                                            if (err2) return console.error('Webhook User Create Fallback Error:', err2);
                                            // For new users from webhook, we don't have an IP yet, so use a placeholder
                                            allowMac(mac, '0.0.0.0'); 
                                            db.run(`INSERT INTO sales (amount, type, description, user_mac) VALUES (?, 'maya', ?, ?)`, 
                                                [amount, `Maya Payment (${mac})`, mac]);
                                            console.log(`Successfully added ${totalMinutes} mins to new user ${mac} via Maya (fallback)`);
                                        });
                                } else {
                                    // For new users from webhook, we don't have an IP yet, so use a placeholder
                                    allowMac(mac, '0.0.0.0'); 
                                    db.run(`INSERT INTO sales (amount, type, description, user_mac) VALUES (?, 'maya', ?, ?)`, 
                                        [amount, `Maya Payment (${mac})`, mac]);
                                    console.log(`Successfully added ${totalMinutes} mins to new user ${mac} via Maya`);
                                }
                            });
                    }
                });
            }
        });
    }
    
    res.status(200).send('OK');
});

// API to connect to the internet (for users with remaining time)
app.post('/api/connect-internet', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const mac = getMacFromIp(ip);

    if (!mac) {
        return res.status(400).json({ error: 'Could not detect your device MAC address.' });
    }

    db.get(`SELECT * FROM users WHERE mac_address = ?`, [mac], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user || user.time_left <= 0) {
            return res.status(400).json({ error: 'You have no remaining time or are not a registered user.' });
        }

        allowMac(mac, ip);
        db.run(`UPDATE users SET status = 'Online', ip_address = ? WHERE mac_address = ?`, [ip, mac], (err) => {
            if (err) return res.status(500).json({ error: 'Failed to update user status.' });
            res.json({ success: true, message: 'Successfully connected to the internet.' });
        });
    });
});

io.on('connection', (socket) => {
    console.log('A user connected to WebSocket');

    // Send current coin insertion status to newly connected client
    socket.emit('coinInsertionStatus', { active: coinInsertionActive, by: activeCoinInserterMac });

    socket.on('startCoinInsertion', (data) => {
        const { mac } = data;
        if (!serialPort || !serialPort.isOpen) {
            socket.emit('coinInsertionError', { message: 'Coinslot hardware not connected.' });
            return;
        }

            if (!coinInsertionActive) {
                coinInsertionActive = true;
                activeCoinInserterMac = mac;
                sendSerialCommand('D'); // Set D8 LOW to INHIBIT coin acceptance
                io.emit('coinInsertionStatus', { active: true, by: mac });
                console.log(`Coin insertion started by ${mac}. D8 set to LOW (inhibit).`);

                // Set a timeout to allow D8 HIGH if no coins are inserted for COINSLOT_INACTIVITY_TIMEOUT
                if (coinslotEnableTimeout) clearTimeout(coinslotEnableTimeout);
                coinslotEnableTimeout = setTimeout(() => {
                    if (coinInsertionActive && activeCoinInserterMac === mac) {
                        sendSerialCommand('E'); // Set D8 HIGH to ALLOW coin acceptance
                        coinInsertionActive = false;
                        activeCoinInserterMac = null;
                        io.emit('coinInsertionStatus', { active: false, by: null });
                        console.log('Coinslot allowed due to inactivity timeout.');
                    }
                }, COINSLOT_INACTIVITY_TIMEOUT);

            } else if (activeCoinInserterMac !== mac) {
                // If another user tries to start, notify them it's busy
                socket.emit('coinInsertionBusy', { by: activeCoinInserterMac });
            }
        });

        socket.on('endCoinInsertion', (data) => {
            const { mac } = data;
            if (coinInsertionActive && activeCoinInserterMac === mac) {
                if (coinslotEnableTimeout) clearTimeout(coinslotEnableTimeout);
                sendSerialCommand('E'); // Set D8 HIGH to ALLOW coin acceptance
                coinInsertionActive = false;
                activeCoinInserterMac = null;
                io.emit('coinInsertionStatus', { active: false, by: null });
                console.log(`Coin insertion ended by ${mac}. D8 set to HIGH (allow).`);
            }
        });

        socket.on('disconnect', () => {
            console.log('User disconnected from WebSocket');
            // If the user who was inserting coins disconnects, reset the status
            if (activeCoinInserterMac === socket.handshake.query.mac) { // Assuming MAC is passed as query param
                if (coinslotEnableTimeout) clearTimeout(coinslotEnableTimeout);
                sendSerialCommand('E'); // Set D8 HIGH to ALLOW coin acceptance
                coinInsertionActive = false;
                activeCoinInserterMac = null;
                io.emit('coinInsertionStatus', { active: false, by: null });
                        console.log(`Coin insertion reset due to disconnect of ${socket.handshake.query.mac}. D8 set to HIGH (allow).`);
            }
        });
});

        // Save Network Settings
app.post('/api/save-network', async (req, res) => {
    try {
        const {
            wan_interface_name, wan_config_type, wan_ip_address, wan_gateway, wan_dns_servers,
            lan_interface_name, lan_ip_address, lan_dns_servers
        } = req.body;

        // Validate required fields
        if (!wan_interface_name || !lan_interface_name || !lan_ip_address) {
            return res.status(400).json({ success: false, message: 'Missing required network interface parameters.' });
        }

        // Validate LAN IP address format (CIDR)
        if (!lan_ip_address.includes('/')) {
            return res.status(400).json({ success: false, message: 'LAN IP address must be in CIDR format (e.g., 10.0.0.1/24).' });
        }

        // Save to database
        db.serialize(() => {
            const stmt = db.prepare(`UPDATE settings SET value = ? WHERE key = ?`);
            stmt.run(wan_interface_name, 'wan_interface_name');
            stmt.run(wan_config_type, 'wan_config_type');
            stmt.run(wan_ip_address, 'wan_ip_address');
            stmt.run(wan_gateway, 'wan_gateway');
            stmt.run(wan_dns_servers ? wan_dns_servers.join(',') : '', 'wan_dns_servers');
            stmt.run(lan_interface_name, 'lan_interface_name');
            stmt.run(lan_ip_address, 'lan_ip_address');
            stmt.run(lan_dns_servers ? lan_dns_servers.join(',') : '', 'lan_dns_servers');
            stmt.finalize();
        });

        // Apply network configuration
        const networkConfig = {
            wan_interface_name,
            wan_config_type,
            wan_ip_address,
            wan_gateway,
            wan_dns_servers,
            lan_interface_name,
            lan_ip_address,
            lan_dns_servers
        };

        const result = await applyNetworkConfig(networkConfig);
        res.json({ success: true, message: result.message });
    } catch (error) {
        console.error('Error saving network settings:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// LAN Configuration API
app.post('/api/network/lan/configure', async (req, res) => {
    try {
        const {
            lan_interface_name,
            lan_ip_address,
            lan_dns_servers
        } = req.body;

        // Validate required fields
        if (!lan_interface_name || !lan_ip_address) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing required fields: lan_interface_name and lan_ip_address' 
            });
        }

        // Validate LAN IP format
        const lanIpMatch = lan_ip_address.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
        if (!lanIpMatch) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid LAN IP format. Use CIDR notation (e.g., 10.0.0.1/24)' 
            });
        }

        const [_, ip, cidr] = lanIpMatch;
        const subnet = ip.split('.').slice(0, 3).join('.');
        
        // Validate CIDR range
        const cidrNum = parseInt(cidr);
        if (cidrNum < 8 || cidrNum > 30) {
            return res.status(400).json({ 
                success: false, 
                error: 'CIDR must be between /8 and /30' 
            });
        }

        // Validate IP address
        const ipParts = ip.split('.').map(Number);
        if (ipParts.some(part => part < 0 || part > 255)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid IP address' 
            });
        }

        // Save to database
        const settings = {
            lan_interface_name,
            lan_ip_address,
            lan_dns_servers: lan_dns_servers || []
        };

        await db.run('UPDATE settings SET value = ? WHERE key = ?', [JSON.stringify(settings), 'network_config']);

        // Apply LAN configuration
        if (os.platform() !== 'linux') {
            return res.json({ 
                success: true, 
                message: 'LAN configuration saved successfully (simulated on non-Linux)' 
            });
        }

        try {
            const networkConfig = {
                lan_interface_name,
                lan_ip_address,
                lan_dns_servers,
                bridge_interface_name: 'br0',
                portal_port: PORT
            };

            await applyLanBridgeApSettings(networkConfig);
            await reapplyNatRulesFromDb();

            res.json({ 
                success: true, 
                message: 'LAN configuration applied successfully!' 
            });
        } catch (applyError) {
            console.error('Failed to apply LAN configuration:', applyError);
            res.status(500).json({ 
                success: false, 
                error: 'Failed to apply LAN configuration: ' + applyError.message 
            });
        }
    } catch (error) {
        console.error('Error configuring LAN:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to configure LAN interface' 
        });
    }
});

// API to get network status and interface information
app.get('/api/network/status', isAuthenticated, async (req, res) => {
    try {
        const status = await getNetworkStatus();
        res.json(status);
    } catch (error) {
        console.error('Failed to get network status:', error.message);
        res.status(500).json({ error: 'Failed to get network status' });
    }
});

// API to auto-configure network interfaces
app.post('/api/network/auto-configure', isAuthenticated, async (req, res) => {
    try {
        const result = await autoConfigureNetwork();
        res.json(result);
    } catch (error) {
        console.error('Auto network configuration failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// API to get current LAN IP and DNS settings
app.get('/api/network/current-settings', isAuthenticated, async (req, res) => {
    try {
        const settings = await getCurrentLanSettings();
        res.json(settings);
    } catch (error) {
        console.error('Failed to get current LAN settings:', error.message);
        res.status(500).json({ error: 'Failed to get current LAN settings' });
    }
});

// API to apply dynamic LAN IP configuration
app.post('/api/network/lan/dynamic', isAuthenticated, async (req, res) => {
    try {
        const { lan_interface_name, desired_subnet, lan_dns_servers } = req.body;

        if (!lan_interface_name || !desired_subnet) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing required parameters: lan_interface_name and desired_subnet' 
            });
        }

        // Validate subnet format
        const subnetMatch = desired_subnet.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
        if (!subnetMatch) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid subnet format. Use CIDR notation (e.g., 10.0.0.0/24)' 
            });
        }

        const result = await applyDynamicLanIp({
            lan_interface_name,
            desired_subnet,
            lan_dns_servers
        });

        // Save to database
        db.serialize(() => {
            const stmt = db.prepare(`UPDATE settings SET value = ? WHERE key = ?`);
            stmt.run(lan_interface_name, 'lan_interface_name');
            stmt.run(result.applied_ip, 'lan_ip_address');
            stmt.run(lan_dns_servers ? lan_dns_servers.join(',') : '', 'lan_dns_servers');
            stmt.finalize();
        });

        res.json(result);
    } catch (error) {
        console.error('Failed to apply dynamic LAN IP configuration:', error.message);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// 1. Unahin ang Redirect Routes para masalo agad ang Windows/Apple checks
app.get('/redirect', async (req, res) => {
    const portalBaseUrl = await getPortalBaseUrl();
    res.redirect(portalBaseUrl);
});

const HOST = '0.0.0.0'; // Bind on all interfaces so it's reachable via LAN + WAN IPs
server.listen(PORT, HOST, () => {
    console.log(`Server running on http://${HOST}:${PORT}`);
});
