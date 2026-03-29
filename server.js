require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const os = require('os');
const { exec, execSync } = require('child_process');
const http = require('http');
const axios = require('axios');
const { SerialPort, ReadlineParser } = require('serialport');

// Import your network services (Siguraduhin na tama ang path nito)
const { 
    sudoExec, 
    loadNetworkSettings,
    normalizeLanIp 
} = require('./services/networkService'); 

const app = express();
const db = new sqlite3.Database(process.env.DATABASE_PATH || './pisowifi.db');
const PORT = process.env.PORT || 3000;
const IPTABLES = '/usr/sbin/iptables';

app.set('trust proxy', true);

// ==========================================
// 1. DYNAMIC NETWORK STARTUP (ANG "UTAK" NG ROUTER)
// ==========================================
async function initializeNetwork() {
    if (os.platform() !== 'linux') return;
    try {
        const settings = await new Promise((resolve) => {
            db.all(`SELECT key, value FROM settings WHERE key IN ('wan_interface_name','lan_interface_name')`, [], (err, rows) => {
                const s = {};
                if (rows) rows.forEach(r => s[r.key] = r.value);
                resolve(s);
            });
        });

        // Dynamic Interfaces: Default sa end0 at enx kung wala sa DB
        const wan = settings.wan_interface_name || 'end0';
        const lan = settings.lan_interface_name || 'enx00e04c680013';

        console.log(`[Network] Initializing: WAN=${wan}, LAN=${lan}`);

        // A. Enable Forwarding
        execSync('sudo /usr/sbin/sysctl -w net.ipv4.ip_forward=1');
        
        // B. Flush Rules (Iwas double entries)
        execSync(`sudo ${IPTABLES} -t nat -F`);
        execSync(`sudo ${IPTABLES} -F FORWARD`);
        
        // C. Internet Sharing (NAT)
        execSync(`sudo ${IPTABLES} -t nat -A POSTROUTING -o ${wan} -j MASQUERADE`);
        
        // D. Forwarding Permissions
        execSync(`sudo ${IPTABLES} -A FORWARD -i ${lan} -o ${wan} -j ACCEPT`);
        execSync(`sudo ${IPTABLES} -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`);
        
        // E. Captive Portal Redirect (Lahat ng papasok sa LAN ay dadaan sa Port 3000)
        execSync(`sudo ${IPTABLES} -t nat -A PREROUTING -i ${lan} -p tcp --dport 80 -j REDIRECT --to-port ${PORT}`);

        console.log(`[Network] System Setup Complete.`);
    } catch (err) {
        console.error('[Network] Error during initialization:', err.message);
    }
}
initializeNetwork();

// ==========================================
// 2. MIDDLEWARES & SESSIONS
// ==========================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'pisowifi-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000, secure: false, sameSite: 'Lax' }
}));

// Captive Portal Redirect Middleware (Inside Node.js)
app.use(async (req, res, next) => {
    try {
        const host = (req.get('host') || '').trim();
        const rawIp = (req.ip || req.connection?.remoteAddress || '').trim();
        const ip = rawIp.replace('::ffff:', '');

        db.get(`SELECT value FROM settings WHERE key = 'lan_ip_address'`, (err, row) => {
            const lanIp = (row ? row.value : '10.0.0.1').split('/')[0];
            const isLanClient = ip.startsWith(lanIp.split('.').slice(0, 3).join('.') + '.');
            const isLocalhost = ip === '127.0.0.1' || ip === '::1';

            if (!isLocalhost && isLanClient) {
                const needsRedirect = !host.startsWith(lanIp) || (host.startsWith(lanIp) && !host.includes(`:${PORT}`));
                if (needsRedirect) {
                    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
                    return res.redirect(`http://${lanIp}:${PORT}${req.originalUrl}`);
                }
            }
            next();
        });
    } catch (err) { next(); }
});

// ==========================================
// 3. PISOWIFI FUNCTIONS (ALLOW / BLOCK MAC)
// ==========================================
async function allowMac(mac) {
    db.get(`SELECT value FROM settings WHERE key = 'lan_interface_name'`, (err, row) => {
        const lan = row ? row.value : 'enx00e04c680013';
        // Insert sa taas ng PREROUTING table (-I 1)
        const cmd = `sudo ${IPTABLES} -t nat -I PREROUTING 1 -i ${lan} -m mac --mac-source ${mac} -j RETURN`;
        exec(cmd, (err) => {
            if (!err) console.log(`[Auth] User Connected: ${mac}`);
        });
    });
}

async function blockMac(mac) {
    db.get(`SELECT value FROM settings WHERE key = 'lan_interface_name'`, (err, row) => {
        const lan = row ? row.value : 'enx00e04c680013';
        const cmd = `sudo ${IPTABLES} -t nat -D PREROUTING -i ${lan} -m mac --mac-source ${mac} -j RETURN`;
        exec(cmd);
    });
}

// ==========================================
// 4. DATABASE & AUTH (REST OF YOUR ROUTES)
// ==========================================
// Dito mo i-paste ulit yung mga original routes mo (app.get('/admin'), login, etc.)

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==========================================
// 5. SERVER START
// ==========================================
const server = http.createServer(app);
const io = require('socket.io')(server);

server.listen(PORT, () => {
    console.log(`PisoWiFi Server is running on port ${PORT}`);
});
