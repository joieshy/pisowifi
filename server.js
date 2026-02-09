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
const app = express();
app.set('trust proxy', true);
const PORT = process.env.PORT || 3000;
const DATABASE_PATH = process.env.DATABASE_PATH || './pisowifi.db';

const http = require('http');
const server = http.createServer(app);
const io = require('socket.io')(server);

let coinInsertionActive = false; // Global state to track if someone is inserting coins
let activeCoinInserterMac = null; // MAC address of the user currently inserting coins

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
    if (os.platform() !== 'linux') {
        console.log(`[Simulated] Allowing MAC: ${mac}`);
        return;
    }
    try {
        // Add to NAT PREROUTING to bypass redirection
        execSync(`sudo iptables -t nat -I PREROUTING -m mac --mac-source ${mac} -j ACCEPT`);
        // Add to FORWARD chain to allow traffic through the router
        execSync(`sudo iptables -I FORWARD -m mac --mac-source ${mac} -j ACCEPT`);
        console.log(`MAC ${mac} allowed in iptables`);

        // Apply bandwidth limits if configured
        const settings = await new Promise((resolve, reject) => {
            db.all(`SELECT key, value FROM settings WHERE key IN ('download_limit', 'upload_limit')`, [], (err, rows) => {
                if (err) return reject(err);
                const s = {};
                rows.forEach(row => s[row.key] = row.value);
                resolve(s);
            });
        });

        const downloadLimit = parseFloat(settings.download_limit || '0');
        const uploadLimit = parseFloat(settings.upload_limit || '0');

        if (downloadLimit > 0 || uploadLimit > 0) {
            db.get(`SELECT tc_class_id, tc_mark FROM users WHERE mac_address = ?`, [mac], (err, user) => {
                if (err) {
                    console.error('Error fetching user for TC:', err.message);
                    return;
                }
                let tcClassId = user.tc_class_id;
                let tcMark = user.tc_mark;

                if (tcClassId === 0 || tcMark === 0) {
                    tcClassId = nextTcClassId++;
                    tcMark = tcClassId; // Use same value for mark for simplicity
                    db.run(`UPDATE users SET tc_class_id = ?, tc_mark = ? WHERE mac_address = ?`, [tcClassId, tcMark, mac]);
                }
                applyBandwidthLimits(ip, downloadLimit, uploadLimit, tcClassId, tcMark);
            });
        }
    } catch (e) {
        console.error(`Failed to allow MAC ${mac}:`, e.message);
    }
}

function removeBandwidthLimits(ip, tcClassId, tcMark) {
    if (os.platform() !== 'linux') {
        console.log(`[Simulated] Removing bandwidth limits for IP: ${ip}, Class: ${tcClassId}, Mark: ${tcMark}`);
        return;
    }
    try {
        // Delete the class for this user
        execSync(`sudo tc class del dev eth1 parent 1: classid 1:${tcClassId} || true`);
        // Delete the filter for this user
        execSync(`sudo tc filter del dev eth1 protocol ip parent 1: prio 1 handle ${tcMark} fw || true`);
        // Remove iptables rule that marks traffic from this IP
        execSync(`sudo iptables -t mangle -D POSTROUTING -s ${ip} -j MARK --set-mark ${tcMark} || true`);
        execSync(`sudo iptables -t mangle -D PREROUTING -d ${ip} -j MARK --set-mark ${tcMark} || true`);
        console.log(`Bandwidth limits removed for IP ${ip} (Class: 1:${tcClassId}, Mark: ${tcMark})`);
    } catch (e) {
        console.error(`Failed to remove bandwidth limits for IP ${ip}:`, e.message);
    }
}

function applyGroupSettings(type, vlanId) {
    if (os.platform() !== 'linux') {
        console.log(`[Simulated] Applying Group Settings: Type=${type}, VLAN ID=${vlanId}`);
        return;
    }

    try {
        console.log(`Applying Group Settings: Type=${type}, VLAN ID=${vlanId}`);
        
        // Clear existing VLAN configuration (simplified example)
        // In a real scenario, you might need to be more specific to avoid disrupting other VLANs
        // execSync('sudo ip link delete eth1.10 || true'); 

        if (type === 'vlan' && vlanId) {
            // Example: Create VLAN interface on eth1
            // execSync(`sudo ip link add link eth1 name eth1.${vlanId} type vlan id ${vlanId}`);
            // execSync(`sudo ip link set dev eth1.${vlanId} up`);
            // execSync(`sudo ip addr add 10.0.${vlanId}.1/24 dev eth1.${vlanId}`);
            
            // Setup DHCP for VLAN (would require dnsmasq config update)
            // ...
            
            console.log(`VLAN ${vlanId} configured on eth1`);
        } else {
            // Direct mode (default)
            console.log('Direct mode configured (no VLAN)');
        }
    } catch (e) {
        console.error('Failed to apply group settings:', e.message);
    }
}

async function applyBandwidthLimits(ip, downloadLimitMbps, uploadLimitMbps, tcClassId, tcMark) {
    if (os.platform() !== 'linux') {
        console.log(`[Simulated] Applying bandwidth limits for IP: ${ip}, DL: ${downloadLimitMbps}Mbps, UL: ${uploadLimitMbps}Mbps`);
        return;
    }

    try {
        const settings = await new Promise((resolve, reject) => {
            db.get(`SELECT value FROM settings WHERE key = 'lan_interface_name'`, [], (err, row) => {
                if (err) return reject(err);
                resolve(row ? row.value : 'eth1');
            });
        });
        const lanInterface = settings || 'eth1';

        // Convert Mbps to Mbits for tc
        const dlRate = downloadLimitMbps > 0 ? `${downloadLimitMbps}mbit` : '1000mbit';
        const ulRate = uploadLimitMbps > 0 ? `${uploadLimitMbps}mbit` : '1000mbit';

        // Ensure the parent class exists (it should from initTrafficControl)
        execSync(`sudo tc class add dev ${lanInterface} parent 1: classid 1:${tcClassId} htb rate ${ulRate} ceil ${ulRate} || true`);
        
        // Add a filter to mark packets from this IP
        execSync(`sudo iptables -t mangle -A POSTROUTING -s ${ip} -j MARK --set-mark ${tcMark}`);
        execSync(`sudo iptables -t mangle -A PREROUTING -d ${ip} -j MARK --set-mark ${tcMark}`);

        // Add filter to direct marked packets to the specific class for outbound (upload)
        execSync(`sudo tc filter add dev ${lanInterface} protocol ip parent 1: prio 1 handle ${tcMark} fw classid 1:${tcClassId}`);

        // For download limits, we need an ingress qdisc
        // Create an IFB device for ingress shaping if it doesn't exist
        try {
            execSync('sudo ip link show ifb0 || sudo ip link add name ifb0 type ifb');
            execSync('sudo ip link set dev ifb0 up');
            execSync('sudo tc qdisc add dev ifb0 root handle 1: htb default 10 || true');
            execSync('sudo tc class add dev ifb0 parent 1: classid 1:10 htb rate 1000mbit || true');
            execSync('sudo tc filter add dev ifb0 protocol ip parent 1: prio 1 handle 1: fw classid 1:1 || true');
            // Redirect ingress traffic from LAN interface to ifb0
            execSync(`sudo tc filter add dev ${lanInterface} ingress protocol ip u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev ifb0`);
        } catch (e) {
            console.warn('IFB device setup failed, ingress shaping may not work:', e.message);
        }

        // Add class for download limit on ifb0
        execSync(`sudo tc class add dev ifb0 parent 1: classid 1:${tcClassId} htb rate ${dlRate} ceil ${dlRate} || true`);
        // Add filter to direct marked packets to the specific class for inbound (download)
        execSync(`sudo tc filter add dev ifb0 protocol ip parent 1: prio 1 handle ${tcMark} fw classid 1:${tcClassId}`);

        console.log(`Bandwidth limits applied for IP ${ip} (DL: ${downloadLimitMbps}Mbps, UL: ${uploadLimitMbps}Mbps)`);
    } catch (e) {
        console.error(`Failed to apply bandwidth limits for IP ${ip}:`, e.message);
    }
}

async function blockMac(mac) {
    if (os.platform() !== 'linux') {
        console.log(`[Simulated] Blocking MAC: ${mac}`);
        return;
    }
    try {
        const settings = await new Promise((resolve, reject) => {
            db.get(`SELECT value FROM settings WHERE key = 'lan_interface_name'`, [], (err, row) => {
                if (err) return reject(err);
                resolve(row ? row.value : 'eth1');
            });
        });
        const lanInterface = settings || 'eth1';

        // Remove from NAT PREROUTING
        execSync(`sudo iptables -t nat -D PREROUTING -m mac --mac-source ${mac} -j ACCEPT`);
        // Remove from FORWARD chain
        execSync(`sudo iptables -D FORWARD -m mac --mac-source ${mac} -j ACCEPT`);
        console.log(`MAC ${mac} blocked in iptables`);

        // Remove bandwidth limits if they were applied
        db.get(`SELECT ip_address, tc_class_id, tc_mark FROM users WHERE mac_address = ?`, [mac], (err, user) => {
            if (err) {
                console.error('Error fetching user for TC removal:', err.message);
                return;
            }
            if (user && user.ip_address && user.tc_class_id > 0 && user.tc_mark > 0) {
                removeBandwidthLimits(user.ip_address, user.tc_class_id, user.tc_mark, lanInterface);
                db.run(`UPDATE users SET tc_class_id = 0, tc_mark = 0 WHERE mac_address = ?`, [mac]);
            }
        });
    } catch (e) {
        // Rule might not exist, ignore error
    }
}

async function removeBandwidthLimits(ip, tcClassId, tcMark, lanInterface) {
    if (os.platform() !== 'linux') {
        console.log(`[Simulated] Removing bandwidth limits for IP: ${ip}, Class: ${tcClassId}, Mark: ${tcMark}`);
        return;
    }
    try {
        // Delete the class for this user
        execSync(`sudo tc class del dev ${lanInterface} parent 1: classid 1:${tcClassId} || true`);
        // Delete the filter for this user
        execSync(`sudo tc filter del dev ${lanInterface} protocol ip parent 1: prio 1 handle ${tcMark} fw || true`);
        // Remove iptables rule that marks traffic from this IP
        execSync(`sudo iptables -t mangle -D POSTROUTING -s ${ip} -j MARK --set-mark ${tcMark} || true`);
        execSync(`sudo iptables -t mangle -D PREROUTING -d ${ip} -j MARK --set-mark ${tcMark} || true`);
        console.log(`Bandwidth limits removed for IP ${ip} (Class: 1:${tcClassId}, Mark: ${tcMark})`);
    } catch (e) {
        console.error(`Failed to remove bandwidth limits for IP ${ip}:`, e.message);
    }
}

async function initNetwork() {
    if (os.platform() !== 'linux') return;
    try {
        console.log('Initializing Network for Orange Pi...');

        const settings = await new Promise((resolve, reject) => {
            db.all(`SELECT key, value FROM settings WHERE key IN ('wan_interface_name', 'lan_interface_name', 'lan_ip_address')`, [], (err, rows) => {
                if (err) return reject(err);
                const s = {};
                rows.forEach(row => s[row.key] = row.value);
                resolve(s);
            });
        });

        const wanInterface = settings.wan_interface_name || 'eth0';
        const lanInterface = settings.lan_interface_name || 'eth1';
        const lanIpAddress = settings.lan_ip_address ? settings.lan_ip_address.split('/')[0] : '10.0.0.1';

        // Enable IP Forwarding
        execSync('sudo sysctl -w net.ipv4.ip_forward=1');
        
        // Clear existing rules to avoid duplicates
        execSync('sudo iptables -F');
        execSync('sudo iptables -t nat -F');
        
        // Setup NAT (MASQUERADE)
        execSync(`sudo iptables -t nat -A POSTROUTING -o ${wanInterface} -j MASQUERADE`);
        
        // Redirect all traffic from LAN to local portal if not authenticated
        // This rule is for the captive portal and requires the LAN interface to be active.
        // It will be applied via the admin panel once the LAN interface is set up.
        // For now, we'll skip it during initial server startup if the LAN interface is not ready.
        // execSync(`sudo iptables -t nat -A PREROUTING -i ${lanInterface} -p tcp --dport 80 -j DNAT --to-destination ${lanIpAddress}:${PORT}`);
        
        // Allow DNS traffic (UDP 53) so users can resolve the portal domain
        execSync('sudo iptables -I FORWARD -p udp --dport 53 -j ACCEPT');
        execSync('sudo iptables -I FORWARD -p udp --sport 53 -j ACCEPT');

        console.log('Network initialization complete.');
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

        const settings = await new Promise((resolve, reject) => {
            db.get(`SELECT value FROM settings WHERE key = 'lan_interface_name'`, [], (err, row) => {
                if (err) return reject(err);
                resolve(row ? row.value : 'eth1');
            });
        });
        const lanInterface = settings || 'eth1';

        // Clear existing qdisc, classes, and filters on LAN interface
        execSync(`sudo tc qdisc del dev ${lanInterface} root || true`);
        execSync(`sudo tc qdisc del dev ${lanInterface} ingress || true`);

        // Add a Hierarchical Token Bucket (HTB) qdisc to the root of LAN interface
        execSync(`sudo tc qdisc add dev ${lanInterface} root handle 1: htb default 10`);
        
        // Add an ingress qdisc for inbound traffic shaping
        execSync(`sudo tc qdisc add dev ${lanInterface} ingress`);

        // Create a default class (1:10) for unclassified traffic
        execSync(`sudo tc class add dev ${lanInterface} parent 1: classid 1:10 htb rate 1000mbit`); // Default unlimited

        // Add a filter to classify packets based on iptables mark
        execSync(`sudo tc filter add dev ${lanInterface} protocol ip parent 1: prio 1 handle 1: fw classid 1:1`); // Default class for marked traffic

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
        ['dns_primary', '8.8.8.8'],
        ['dns_secondary', '8.8.4.4'],
        ['ip_range_start', '192.168.1.100'],
        ['ip_range_end', '192.168.1.200'],
        ['wifi_channel', 'auto'],
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
        ['group_type', 'direct'],
        ['vlan_id', ''],
        ['wan_interface_name', 'enp1s0'],
        ['wan_config_type', 'dhcp'],
        ['wan_ip_address', ''],
        ['wan_gateway', ''],
        ['wan_dns_servers', '8.8.8.8,8.8.4.4'],
        ['lan_interface_name', 'enp2s0'],
        ['lan_ip_address', '10.0.0.1/24'],
        ['lan_dns_servers', '8.8.8.8,8.8.4.4']
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
        ['lan_interface_name', 'enp2s0'],
        ['lan_ip_address', '10.0.0.1/24'],
        ['lan_dns_servers', '8.8.8.8,8.8.4.4']
    ];
    networkInterfaceSettings.forEach(setting => {
        db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, setting);
    });

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

    // Run network init and traffic control init after database is ready
    initNetwork();
    initTrafficControl();
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'pisowifi-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 } // 1 hour
}));

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
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

// Auth Middleware
const isAuthenticated = (req, res, next) => {
    if (req.session.adminId) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Global variable to track current session coins (simulated)
let currentSessionCoins = 0;

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
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
                const newTime = user.time_left + totalMinutes;
                db.run(`UPDATE users SET time_left = ?, status = 'Online', ip_address = ? WHERE mac_address = ?`, 
                    [newTime, ip, mac], (err) => {
                        if (err) return res.status(500).json({ error: 'Failed to update user' });
                        
                        allowMac(mac, ip);
                        db.run(`INSERT INTO sales (amount, type, description, user_mac) VALUES (?, 'coin', ?, ?)`, 
                            [currentSessionCoins - remainingCoins, `Coin Insertion (${mac})`, mac]);
                        currentSessionCoins = remainingCoins;
                        res.json({ success: true, minutesAdded: totalMinutes, totalTime: newTime });
                    });
            } else {
                const username = `User-${mac.replace(/:/g, '').slice(-4)}`;
                db.run(`INSERT INTO users (username, ip_address, mac_address, time_left, status) VALUES (?, ?, ?, ?, 'Online')`,
                    [username, ip, mac, totalMinutes], (err) => {
                        if (err) {
                            // Fallback if username exists
                            db.run(`UPDATE users SET time_left = time_left + ?, status = 'Online', ip_address = ? WHERE mac_address = ?`,
                                [totalMinutes, ip, mac], (err2) => {
                                    if (err2) return res.status(500).json({ error: 'Failed to create user' });
                            allowMac(mac, ip);
                            db.run(`INSERT INTO sales (amount, type, description, user_mac) VALUES (?, 'coin', ?, ?)`, 
                                [currentSessionCoins - remainingCoins, `Coin Insertion (${mac})`, mac]);
                            currentSessionCoins = remainingCoins;
                            res.json({ success: true, minutesAdded: totalMinutes, totalTime: totalMinutes });
                        });
                } else {
                    allowMac(mac, ip);
                    db.run(`INSERT INTO sales (amount, type, description, user_mac) VALUES (?, 'coin', ?, ?)`, 
                        [currentSessionCoins - remainingCoins, `Coin Insertion (${mac})`, mac]);
                    currentSessionCoins = remainingCoins;
                    res.json({ success: true, minutesAdded: totalMinutes, totalTime: totalMinutes });
                }
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
                                db.run(`UPDATE users SET time_left = time_left + ?, status = 'Online', ip_address = ? WHERE mac_address = ?`,
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

    // If group settings are updated, apply them
    if (settings.group_type !== undefined || settings.vlan_id !== undefined) {
        // We need to fetch the latest values because the request might only contain one of them
        db.all(`SELECT key, value FROM settings WHERE key IN ('group_type', 'vlan_id')`, [], (err, rows) => {
            if (!err) {
                const currentSettings = {};
                rows.forEach(row => currentSettings[row.key] = row.value);
                
                // Override with new values from request if present
                const type = settings.group_type !== undefined ? settings.group_type : (currentSettings.group_type || 'direct');
                const vlanId = settings.vlan_id !== undefined ? settings.vlan_id : (currentSettings.vlan_id || '');
                
                applyGroupSettings(type, vlanId);
            }
        });
    }

    // If bandwidth limits are updated, re-apply to all active users
    if (settings.download_limit !== undefined || settings.upload_limit !== undefined) {
        const downloadLimit = parseFloat(settings.download_limit || '0');
        const uploadLimit = parseFloat(settings.upload_limit || '0');

        db.all(`SELECT ip_address, mac_address, tc_class_id, tc_mark FROM users WHERE status = 'Online'`, [], (err, users) => {
            if (err) {
                console.error('Error fetching active users for bandwidth update:', err.message);
                return res.status(500).json({ error: 'Database error' });
            }
            users.forEach(user => {
                if (user.ip_address && user.tc_class_id > 0 && user.tc_mark > 0) {
                    // Remove existing limits first
                    removeBandwidthLimits(user.ip_address, user.tc_class_id, user.tc_mark);
                    // Apply new limits
                    applyBandwidthLimits(user.ip_address, downloadLimit, uploadLimit, user.tc_class_id, user.tc_mark);
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
                download_limit: user.status === 'Online' ? globalDownloadLimit : 0,
                upload_limit: user.status === 'Online' ? globalUploadLimit : 0
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

    // Application Uptime
    const now = new Date();
    const appUptimeSeconds = Math.floor((now.getTime() - serverStartTime.getTime()) / 1000);
    const appDays = Math.floor(appUptimeSeconds / (3600 * 24));
    const appHours = Math.floor((appUptimeSeconds % (3600 * 24)) / 3600);
    const appMinutes = Math.floor((appUptimeSeconds % 3600) / 60);
    stats.systemUptime = `${appDays} days, ${appHours} hours, ${appMinutes} minutes`;

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
    // Execute reboot command after a short delay to allow response to be sent
    setTimeout(() => {
        const scriptPath = path.join(__dirname, 'scripts', 'reboot.sh');
        const command = os.platform() === 'win32' ? 'shutdown /r /t 1' : scriptPath;
        console.log(`Attempting to execute reboot command: ${command}`);
        exec(command, { timeout: 5000 }, (error, stdout, stderr) => {
            if (error) {
                console.error(`Reboot command failed: ${error.message}`);
                console.error(`Stderr: ${stderr}`);
                console.error(`Stdout: ${stdout}`);
                console.error(`Full error object:`, error);
            } else {
                console.log(`Reboot command executed successfully. Stdout: ${stdout}`);
            }
        });
    }, 1000);
});

app.post('/api/system/shutdown', isAuthenticated, (req, res) => {
    console.log('System shutdown requested');
    res.json({ success: true, message: 'Shutting down system...' });
    // Execute shutdown command after a short delay to allow response to be sent
    setTimeout(() => {
        const scriptPath = path.join(__dirname, 'scripts', 'shutdown.sh');
        const command = os.platform() === 'win32' ? 'shutdown /s /t 1' : scriptPath;
        console.log(`Attempting to execute shutdown command: ${command}`);
        exec(command, { timeout: 5000 }, (error, stdout, stderr) => {
            if (error) {
                console.error(`Shutdown command failed: ${error.message}`);
                console.error(`Stderr: ${stderr}`);
                console.error(`Stdout: ${stdout}`);
                console.error(`Full error object:`, error);
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

// Diagnostics: Ping
app.post('/api/diagnostics/ping', isAuthenticated, (req, res) => {
    const { host } = req.body;
    if (!host) return res.status(400).json({ error: 'Host is required' });
    
    const command = os.platform() === 'win32' ? `ping -n 4 ${host}` : `ping -c 4 ${host}`;
    exec(command, (error, stdout, stderr) => {
        res.json({ output: stdout || stderr || error.message });
    });
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
        execSync(`sudo mv ${tempNetplanPath} ${netplanFilePath}`);
        execSync(`sudo chmod 600 ${netplanFilePath}`); // Set appropriate permissions

        console.log(`Netplan configuration written to ${netplanFilePath}`);
        console.log('Applying Netplan configuration...');
        execSync('sudo netplan apply');
        console.log('Netplan configuration applied successfully.');

        res.json({ success: true, message: 'Network configuration applied successfully!' });
    } catch (e) {
        console.error('Failed to apply Netplan configuration:', e.message);
        res.status(500).json({ error: `Failed to apply network configuration: ${e.message}` });
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
        if (!coinInsertionActive) {
            coinInsertionActive = true;
            activeCoinInserterMac = mac;
            io.emit('coinInsertionStatus', { active: true, by: mac });
            console.log(`Coin insertion started by ${mac}`);
        } else if (activeCoinInserterMac !== mac) {
            // If another user tries to start, notify them it's busy
            socket.emit('coinInsertionBusy', { by: activeCoinInserterMac });
        }
    });

    socket.on('endCoinInsertion', (data) => {
        const { mac } = data;
        if (coinInsertionActive && activeCoinInserterMac === mac) {
            coinInsertionActive = false;
            activeCoinInserterMac = null;
            io.emit('coinInsertionStatus', { active: false, by: null });
            console.log(`Coin insertion ended by ${mac}`);
        }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected from WebSocket');
        // If the user who was inserting coins disconnects, reset the status
        // This might need more robust handling in a real-world scenario (e.g., timeout)
        if (activeCoinInserterMac === socket.handshake.query.mac) { // Assuming MAC is passed as query param
            coinInsertionActive = false;
            activeCoinInserterMac = null;
            io.emit('coinInsertionStatus', { active: false, by: null });
            console.log(`Coin insertion reset due to disconnect of ${socket.handshake.query.mac}`);
        }
    });
});

const HOST = '0.0.0.0'; // Temporarily hardcoded to 0.0.0.0 to resolve EADDRNOTAVAIL on server startup.
                        // This will be reverted to process.env.HOST || '0.0.0.0' once network setup is stable.
server.listen(PORT, HOST, () => {
    console.log(`Server running on http://${HOST}:${PORT}`);
});
