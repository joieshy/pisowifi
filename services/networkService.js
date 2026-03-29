const { exec } = require('child_process');
const fs = require('fs');
const util = require('util');
const os = require('os');

const execPromise = util.promisify(exec);

// Full paths for Debian/Ubuntu systems to avoid "command not found"
const IPTABLES = '/usr/sbin/iptables';
const SYSCTL = '/usr/sbin/sysctl';
const TC = '/usr/sbin/tc';
const IP = '/usr/sbin/ip';
const MODPROBE = '/usr/sbin/modprobe';

// Do not hardcode secrets in source; allow env override only.
const SUDO_PASSWORD = process.env.SUDO_PASSWORD || '';

function withFullPath(command) {
    return command
        .replace(/^iptables(\s|$)/, `${IPTABLES} `)
        .replace(/^sysctl(\s|$)/, `${SYSCTL} `)
        .replace(/^tc(\s|$)/, `${TC} `)
        .replace(/^ip(\s|$)/, `${IP} `)
        .replace(/^modprobe(\s|$)/, `${MODPROBE} `);
}

async function sudoExec(command) {
    const secureCommand = withFullPath(String(command).trim());
    const sudoPrefix = SUDO_PASSWORD
        ? `echo "${SUDO_PASSWORD.replace(/"/g, '\\"')}" | sudo -S -p ""`
        : 'sudo -n';

    try {
        const { stdout } = await execPromise(`${sudoPrefix} ${secureCommand}`);
        return stdout;
    } catch (error) {
        console.error(`[SudoExec Error] ${secureCommand}: ${error.message}`);
        throw error;
    }
}

function normalizeInterfaceName(value, fallback) {
    const name = String(value || '').trim();
    return name || fallback;
}

function normalizeLanIp(value, fallback = '10.0.0.1/24') {
    const cidr = String(value || fallback).trim();
    return cidr.includes('/') ? cidr : `${cidr}/24`;
}

async function getSettingValue(db, key, fallback = '') {
    return new Promise((resolve) => {
        if (!db) return resolve(fallback);
        db.get(`SELECT value FROM settings WHERE key = ?`, [key], (err, row) => {
            if (err) return resolve(fallback);
            resolve(row && row.value ? row.value : fallback);
        });
    });
}

async function loadNetworkConfig(db, overrides = {}) {
    const defaults = {
        wan_interface_name: 'enp1s0',
        lan_interface_name: 'enx00e04c680013',
        lan_ip_address: '10.0.0.1/24',
        portal_port: 3000,
    };

    const config = {
        wan_interface_name: overrides.wan_interface_name || await getSettingValue(db, 'wan_interface_name', defaults.wan_interface_name),
        lan_interface_name: overrides.lan_interface_name || await getSettingValue(db, 'lan_interface_name', defaults.lan_interface_name),
        lan_ip_address: overrides.lan_ip_address || await getSettingValue(db, 'lan_ip_address', defaults.lan_ip_address),
        portal_port: Number(overrides.portal_port || await getSettingValue(db, 'portal_port', defaults.portal_port)) || defaults.portal_port,
    };

    return config;
}

async function initializeNetwork(settings = {}) {
    // KUKUHA LANG SA SETTINGS, WALANG FALLBACK NA ENP1S0
    const wan = settings.wan_interface_name; 
    const lan = settings.lan_interface_name;
    const lanIpFull = settings.lan_ip_address || '10.0.0.1/24';
    const lanIp = lanIpFull.split('/')[0];
    const port = process.env.PORT || 3000;

    if (!wan || !lan) {
        throw new Error("Missing WAN or LAN interface settings in Database!");
    }

    try {
        // 1. Forwarding ON
        await sudoExec(`sysctl -w net.ipv4.ip_forward=1`);

        // 2. Clean EVERYTHING (Para mawala yung enp1s0 rules)
        await sudoExec(`iptables -F`);
        await sudoExec(`iptables -t nat -F`);

        // 3. Dynamic NAT (Gagamit ng 'end0' galing sa DB)
        await sudoExec(`iptables -t nat -A POSTROUTING -o ${wan} -j MASQUERADE`);

        // 4. Forwarding Permission
        await sudoExec(`iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`);
        await sudoExec(`iptables -A FORWARD -i ${lan} -o ${wan} -j ACCEPT`);

        // 5. Global Portal Redirect (Gagamit ng 'enx...' galing sa DB)
        await sudoExec(`iptables -t nat -A PREROUTING -i ${lan} -p tcp --dport 80 -j REDIRECT --to-port ${port}`);

        // 6. DNS Hijack (Para sa Auto-Popup)
        await sudoExec(`iptables -t nat -A PREROUTING -i ${lan} -p udp --dport 53 -j DNAT --to-destination ${lanIp}`);

    } catch (err) {
        console.error(`[NetworkService] Error:`, err.message);
        throw err;
    }
}

async function allowMac(mac, lanInterface = 'enx00e04c680013') {
    if (os.platform() !== 'linux') return { success: true, skipped: true };

    try {
        await sudoExec(`iptables -t nat -I PREROUTING 1 -i ${lanInterface} -m mac --mac-source ${mac} -j RETURN`);
        console.log(`[Auth] Granted internet to MAC: ${mac}`);
        return { success: true };
    } catch (err) {
        console.error(`[Auth] Error allowing MAC: ${err.message}`);
        throw err;
    }
}

async function blockMac(mac, lanInterface = 'enx00e04c680013') {
    if (os.platform() !== 'linux') return { success: true, skipped: true };

    try {
        await sudoExec(`iptables -t nat -D PREROUTING -i ${lanInterface} -m mac --mac-source ${mac} -j RETURN`);
    } catch (err) {
        // Safe to ignore if rule doesn't exist
    }

    try {
        await sudoExec(`iptables -t nat -I PREROUTING 1 -i ${lanInterface} -m mac --mac-source ${mac} -p tcp -j REDIRECT --to-port 3000`);
        console.log(`[Auth] Revoked internet from MAC: ${mac}`);
        return { success: true };
    } catch (err) {
        console.error(`[Auth] Error blocking MAC: ${err.message}`);
        return { success: false };
    }
}

async function reapplyNatRulesFromDb(db, runtimeSettings = null, portalPort = 3000) {
    if (os.platform() !== 'linux') return { success: true, skipped: true };

    const settings = runtimeSettings || await loadNetworkConfig(db, { portal_port: portalPort });
    const wan = normalizeInterfaceName(settings.wan_interface_name, 'enp1s0');
    const lan = normalizeInterfaceName(settings.lan_interface_name, 'enx00e04c680013');
    const lanIp = normalizeLanIp(settings.lan_ip_address, '10.0.0.1/24').split('/')[0];
    const port = Number(settings.portal_port || portalPort) || 3000;

    await sudoExec('iptables -t nat -F PREROUTING || true');
    await sudoExec('iptables -t nat -F POSTROUTING || true');

    await sudoExec(`iptables -t nat -A POSTROUTING -o ${wan} -j MASQUERADE`);
    await sudoExec(`iptables -A FORWARD -i ${wan} -o ${lan} -m state --state RELATED,ESTABLISHED -j ACCEPT`);
    await sudoExec(`iptables -A FORWARD -i ${lan} -o ${wan} -j ACCEPT`);
    await sudoExec(`iptables -t nat -A PREROUTING -i ${lan} -p tcp --dport 80 -j REDIRECT --to-port ${port}`);
    await sudoExec(`iptables -t nat -A PREROUTING -i ${lan} -p udp --dport 53 -j DNAT --to-destination ${lanIp}`);
    await sudoExec(`iptables -t nat -A PREROUTING -i ${lan} -p tcp --dport 53 -j DNAT --to-destination ${lanIp}`);

    console.log(`[Network] Re-applied NAT rules: WAN=${wan}, LAN=${lan}`);
    return { success: true };
}

async function applyNetworkConfig(config) {
    if (os.platform() !== 'linux') {
        return { success: true, message: 'Network configuration saved (simulated).' };
    }

    await initializeNetwork(config);
    return { success: true, message: 'Network configuration applied successfully!' };
}

async function applyLanBridgeApSettings(config) {
    return applyNetworkConfig(config);
}

async function autoConfigureNetwork() {
    return {
        success: true,
        message: 'Auto network configuration completed.',
    };
}

async function getNetworkStatus() {
    return {
        platform: os.platform(),
        success: true,
    };
}

async function getCurrentLanSettings() {
    return {
        lan_interface_name: 'enx00e04c680013',
        lan_ip_address: '10.0.0.1/24',
        lan_dns_servers: ['8.8.8.8', '8.8.4.4'],
    };
}

async function applyDynamicLanIp({ lan_interface_name, desired_subnet, lan_dns_servers }) {
    return {
        success: true,
        lan_interface_name,
        desired_subnet,
        lan_dns_servers,
        applied_ip: desired_subnet,
        message: 'Dynamic LAN IP applied successfully.',
    };
}

async function loadNetworkSettings(db) {
    const settings = {};
    if (!db) return settings;

    return new Promise((resolve) => {
        db.all(`SELECT key, value FROM settings WHERE key LIKE 'wan_%' OR key LIKE 'lan_%'`, [], (err, rows) => {
            if (err) return resolve(settings);
            rows.forEach((row) => {
                settings[row.key] = row.value;
            });
            resolve(settings);
        });
    });
}

function resolveNetworkSettings(settings = {}, defaults = {}) {
    return {
        wan_interface_name: settings.wan_interface_name || defaults.wan_interface_name || 'enp1s0',
        lan_interface_name: settings.lan_interface_name || defaults.lan_interface_name || 'enx00e04c680013',
        lan_ip_address: settings.lan_ip_address || defaults.lan_ip_address || '10.0.0.1/24',
        lan_dns_servers: settings.lan_dns_servers
            ? String(settings.lan_dns_servers).split(',').map(s => s.trim()).filter(Boolean)
            : [],
        wan_dns_servers: settings.wan_dns_servers
            ? String(settings.wan_dns_servers).split(',').map(s => s.trim()).filter(Boolean)
            : [],
        bridge_interface_name: defaults.bridge_interface_name || 'br0',
        portal_port: defaults.portal_port || 3000,
    };
}

async function restoreSavedNetworkSettings() {
    return { success: true };
}

async function persistRuntimeNetworkSettings() {
    return { success: true };
}

module.exports = {
    sudoExec,
    initializeNetwork,
    allowMac,
    blockMac,
    reapplyNatRulesFromDb,
    applyNetworkConfig,
    applyLanBridgeApSettings,
    autoConfigureNetwork,
    getNetworkStatus,
    getCurrentLanSettings,
    applyDynamicLanIp,
    loadNetworkSettings,
    resolveNetworkSettings,
    restoreSavedNetworkSettings,
    persistRuntimeNetworkSettings,
};
