const { exec } = require('child_process');
const fs = require('fs');
const util = require('util');
const execPromise = util.promisify(exec);

const SUDO_PASSWORD = process.env.SUDO_PASSWORD || 'Alexjoy-1623';

function detectDefaultWifiInterface() {
    try {
        // prefer: wlan0, then wlp* (common on Debian), then any wlan*
        const output = require('child_process').execSync('ls /sys/class/net 2>/dev/null').toString();
        const ifaces = output.split('\n').map(s => s.trim()).filter(Boolean);

        if (ifaces.includes('wlan0')) return 'wlan0';

        const wlp = ifaces.find(n => n.startsWith('wlp'));
        if (wlp) return wlp;

        const wlan = ifaces.find(n => n.startsWith('wlan'));
        if (wlan) return wlan;

        return 'wlan0';
    } catch (e) {
        return 'wlan0';
    }
}

function ipToInt(ip) {
    return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}

function intToIp(int) {
    return [
        (int >>> 24) & 255,
        (int >>> 16) & 255,
        (int >>> 8) & 255,
        int & 255
    ].join('.');
}

function cidrToMask(prefix) {
    const p = parseInt(prefix, 10);
    if (Number.isNaN(p) || p < 0 || p > 32) throw new Error(`Invalid CIDR prefix: ${prefix}`);
    const maskInt = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
    return intToIp(maskInt);
}

/**
 * Parse "10.0.0.1/24" -> { ip: '10.0.0.1', prefix: 24 }
 */
function parseCidr(cidr) {
    if (!cidr || typeof cidr !== 'string') throw new Error('LAN IP address is required (CIDR format, e.g., 10.0.0.1/24)');
    const trimmed = cidr.trim();
    const parts = trimmed.split('/');
    if (parts.length !== 2) throw new Error(`Invalid CIDR format: ${cidr}`);
    const ip = parts[0].trim();
    const prefix = parseInt(parts[1].trim(), 10);
    if (!ip.match(/^\d+\.\d+\.\d+\.\d+$/)) throw new Error(`Invalid IPv4 address in CIDR: ${cidr}`);
    if (Number.isNaN(prefix) || prefix < 1 || prefix > 30) throw new Error(`CIDR prefix must be between 1 and 30: ${cidr}`);
    return { ip, prefix };
}

/**
 * Compute DHCP range inside the CIDR.
 * - reserves network, broadcast
 * - reserves gateway IP
 * - returns a practical range: start = network+10 (or next after gateway), end = broadcast-1
 */
function computeDhcpRange(gatewayIp, prefix) {
    const gwInt = ipToInt(gatewayIp);
    const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const networkInt = (gwInt & maskInt) >>> 0;
    const broadcastInt = (networkInt | (~maskInt >>> 0)) >>> 0;

    const firstUsable = networkInt + 1;
    const lastUsable = broadcastInt - 1;

    // Prefer starting from network+10 to avoid conflicts with infra addresses
    let start = networkInt + 10;
    if (start < firstUsable) start = firstUsable;

    // Ensure start isn't the gateway
    if (start === gwInt) start += 1;

    const end = lastUsable;

    if (start > end) {
        throw new Error(`CIDR too small for DHCP range: ${gatewayIp}/${prefix}`);
    }

    return {
        start: intToIp(start),
        end: intToIp(end),
        netmask: cidrToMask(prefix),
        network: intToIp(networkInt),
        broadcast: intToIp(broadcastInt)
    };
}

function hasIptables() {
    try {
        require('child_process').execSync('iptables -V', { stdio: 'ignore' });
        return true;
    } catch (e1) {
        try {
            require('child_process').execSync('which iptables', { stdio: 'ignore' });
            return true;
        } catch (e2) {
            return false;
        }
    }
}

// Helper function to execute sudo commands with fallback
async function sudoExec(command) {
    try {
        // Use -S to read password from stdin
        return await execPromise(`echo "${SUDO_PASSWORD}" | sudo -S ${command}`);
    } catch (sudoError) {
        console.warn(`sudo command failed with password for: ${command}, trying without sudo...`);
        try {
            return await execPromise(command);
        } catch (error) {
            throw new Error(`Failed to execute command: ${error.message}. Original sudo error: ${sudoError.message}`);
        }
    }
}

// Helper function to generate Netplan YAML content
function generateNetplanConfig(wanInterface, wanConfigType, wanIp, wanGateway, wanDns, lanInterface, lanIp, lanDns) {
    let config = `network:
  version: 2
  renderer: networkd
  ethernets:
`;

    // WAN Interface
    config += `    ${wanInterface}:\n`;
    if (wanConfigType === 'dhcp') {
        config += `      dhcp4: true\n`;
    } else { // Static WAN
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

async function applyNetworkConfig(config) {
    const {
        wan_interface_name, wan_config_type, wan_ip_address, wan_gateway, wan_dns_servers,
        lan_interface_name, lan_ip_address, lan_dns_servers
    } = config;

    if (!wan_interface_name || !lan_interface_name || !lan_ip_address) {
        throw new Error('Missing required network interface parameters.');
    }

    if (process.platform !== 'linux') {
        console.log('[Simulated] Network configuration skipped on non-Linux platform.');
        return { success: true, message: 'Network configuration saved (simulated).' };
    }

    // Debian may not have netplan. Prefer netplan when available, otherwise use ifupdown (/etc/network/interfaces).
    const hasNetplan = async () => {
        try {
            await execPromise('command -v netplan');
            return true;
        } catch (e) {
            return false;
        }
    };

    try {
        if (await hasNetplan()) {
            const netplanConfig = generateNetplanConfig(
                wan_interface_name, wan_config_type, wan_ip_address, wan_gateway, wan_dns_servers,
                lan_interface_name, lan_ip_address, lan_dns_servers
            );

            const netplanFilePath = `/etc/netplan/01-pisowifi-config.yaml`;
            const tempNetplanPath = `/tmp/01-pisowifi-config.yaml.tmp`;

            fs.writeFileSync(tempNetplanPath, netplanConfig);
            await sudoExec(`mkdir -p /etc/netplan`);
            await sudoExec(`mv ${tempNetplanPath} ${netplanFilePath}`);
            await sudoExec(`chmod 600 ${netplanFilePath}`);

            console.log(`Netplan configuration written to ${netplanFilePath}`);
            console.log('Applying Netplan configuration...');
            await sudoExec('netplan apply');
            console.log('Netplan configuration applied successfully.');

            return { success: true, message: 'Network configuration applied successfully (netplan)!' };
        }

        // Fallback: /etc/network/interfaces (ifupdown)
        // NOTE: This is a best-effort minimal config. On Debian, users commonly install ifupdown or use NetworkManager/systemd-networkd.
        const interfacesPath = '/etc/network/interfaces';
        const wanDnsList = (wan_dns_servers && wan_dns_servers.length > 0) ? wan_dns_servers : [];
        const lanDnsList = (lan_dns_servers && lan_dns_servers.length > 0) ? lan_dns_servers : [];

        const lines = [];
        lines.push('# Generated by PisoWiFi');
        lines.push('auto lo');
        lines.push('iface lo inet loopback');
        lines.push('');

        // WAN
        lines.push(`auto ${wan_interface_name}`);
        if (wan_config_type === 'dhcp') {
            lines.push(`iface ${wan_interface_name} inet dhcp`);
        } else {
            lines.push(`iface ${wan_interface_name} inet static`);
            if (wan_ip_address) lines.push(`  address ${wan_ip_address.split('/')[0]}`);
            // netmask from CIDR if provided, else user should provide full config
            if (wan_ip_address && wan_ip_address.includes('/')) {
                const { prefix } = parseCidr(wan_ip_address);
                lines.push(`  netmask ${cidrToMask(prefix)}`);
            }
            if (wan_gateway) lines.push(`  gateway ${wan_gateway}`);
            if (wanDnsList.length > 0) lines.push(`  dns-nameservers ${wanDnsList.join(' ')}`);
        }
        lines.push('');

        // LAN (no DHCP)
        lines.push(`auto ${lan_interface_name}`);
        lines.push(`iface ${lan_interface_name} inet static`);
        if (lan_ip_address) {
            const { ip, prefix } = parseCidr(lan_ip_address);
            lines.push(`  address ${ip}`);
            lines.push(`  netmask ${cidrToMask(prefix)}`);
        }
        if (lanDnsList.length > 0) lines.push(`  dns-nameservers ${lanDnsList.join(' ')}`);
        lines.push('');

        fs.writeFileSync('/tmp/pisowifi-interfaces', lines.join('\n'));
        await sudoExec(`cp /tmp/pisowifi-interfaces ${interfacesPath}`);

        // Best-effort restart
        await sudoExec(`ifdown ${wan_interface_name} 2>/dev/null || true`);
        await sudoExec(`ifdown ${lan_interface_name} 2>/dev/null || true`);
        await sudoExec(`ifup ${wan_interface_name} 2>/dev/null || true`);
        await sudoExec(`ifup ${lan_interface_name} 2>/dev/null || true`);

        return { success: true, message: 'Network configuration applied successfully (/etc/network/interfaces fallback)!' };
    } catch (e) {
        console.error('Failed to apply network configuration:', e.message);
        throw new Error(`Failed to apply network configuration: ${e.message}`);
    }
}

// ============================================
// NEW NETWORK SETTINGS FUNCTIONS
// ============================================

// 1. WiFi Settings - Configure hostapd for WiFi access point
async function applyWifiSettings(config) {
    const {
        wifi_ssid,
        wifi_password,
        wifi_security,
        wifi_max_users,
        wifi_transmit_power,
        wifi_hidden,
        wifi_interface_name
    } = config;

    if (process.platform !== 'linux') {
        console.log('[Simulated] WiFi settings skipped on non-Linux platform.');
        return { success: true, message: 'WiFi settings saved (simulated).' };
    }

    const wifiIface = wifi_interface_name || detectDefaultWifiInterface();

    try {
        const hasSystemctl = async () => {
            try {
                await execPromise('command -v systemctl');
                return true;
            } catch (e) {
                return false;
            }
        };

        const hasHostapd = async () => {
            try {
                await execPromise('hostapd -v');
                return true;
            } catch (e1) {
                try {
                    await execPromise('/usr/sbin/hostapd -v');
                    return true;
                } catch (e2) {
                    try {
                        await execPromise('which hostapd');
                        return true;
                    } catch (e3) {
                        return false;
                    }
                }
            }
        };

        // If hostapd isn't installed, we can still configure the file, but we can't start AP.
        // Return a clear warning so the UI can show it, instead of failing the whole LAN bridge apply.
        if (!(await hasHostapd())) {
            return {
                success: false,
                message: 'hostapd is not installed. WiFi AP cannot be started. Install it on Debian: sudo apt-get update && sudo apt-get install -y hostapd'
            };
        }

        // Generate hostapd configuration
        const ssid = (wifi_ssid || config.wifi_name || config.wifi_ssid || 'PisoWiFi').toString().trim() || 'PisoWiFi';

        // IMPORTANT:
        // Your hostapd debug shows: "ACS: Unable to collect survey data" then "Interface initialization failed".
        // That happens when hostapd is doing ACS (automatic channel selection) but the driver doesn't provide survey data.
        // Fix: force a static channel and disable ACS.
        // Also add ctrl_interface so hostapd doesn't complain "ctrl_iface not configured!".
        // Add WMM/HT (802.11n) for better compatibility.
        let hostapdConfig = `interface=${wifiIface}
driver=nl80211
ssid=${ssid}
country_code=PH

# Disable ACS - force channel (prevents: "Unable to collect survey data")
hw_mode=g
channel=6

# Management interface (prevents: "ctrl_iface not configured!")
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0

# Basic performance/compatibility
wmm_enabled=1
ieee80211n=1
ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40]

# Broadcast SSID by default (overridden below)
ignore_broadcast_ssid=0
`;

        // Security settings
        // NOTE: hw_mode/channel already set above.
        if (wifi_security === 'wpa2') {
            hostapdConfig += `wpa=2
wpa_passphrase=${wifi_password || 'password'}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
`;
        } else if (wifi_security === 'wpa3') {
            hostapdConfig += `wpa=2
wpa_passphrase=${wifi_password || 'password'}
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
`;
        } else if (wifi_security === 'wpa2+wpa3') {
            hostapdConfig += `wpa=2
wpa_passphrase=${wifi_password || 'password'}
wpa_key_mgmt=SAE WPA-PSK
rsn_pairwise=CCMP
ieee80211w=1
`;
        } else {
            // Open network
            hostapdConfig += `wpa=0
`;
        }

        // Max users
        if (wifi_max_users) {
            hostapdConfig += `max_num_station=${wifi_max_users}\n`;
        }

        // Transmit power
        // NOTE: hostapd doesn't support "txpower=" in a portable way.
        // We apply power via `iw` (if available): percent -> mBm where 100% ~= 2000 mBm (20 dBm).
        if (wifi_transmit_power !== undefined && wifi_transmit_power !== null && wifi_transmit_power !== '') {
            const percent = Math.max(1, Math.min(100, parseInt(wifi_transmit_power, 10) || 100));
            const maxMb = 2000; // 20 dBm typical max; hardware-specific
            const txMb = Math.round((percent / 100) * maxMb);

            try {
                await sudoExec(`iw dev ${wifiIface} set txpower fixed ${txMb}`);
            } catch (e) {
                // ignore if iw isn't installed or driver doesn't support it
            }
        }

        // Hidden SSID
        if (wifi_hidden === 'true') {
            hostapdConfig += `ignore_broadcast_ssid=1\n`;
        } else {
            hostapdConfig += `ignore_broadcast_ssid=0\n`;
        }

        // Write hostapd config
        const hostapdPath = '/etc/hostapd/hostapd.conf';
        fs.writeFileSync('/tmp/hostapd.conf', hostapdConfig);

        // Ensure /etc/hostapd directory exists
        await sudoExec('mkdir -p /etc/hostapd');

        // Use sudoExec helper
        await sudoExec(`mv /tmp/hostapd.conf ${hostapdPath}`);
        await sudoExec(`chmod 600 ${hostapdPath}`);

        const startHostapdFallback = async () => {
            // Stop any existing hostapd instance, then start with config.
            await sudoExec('pkill hostapd 2>/dev/null || true');
            await sudoExec(`/usr/sbin/hostapd -B ${hostapdPath} || hostapd -B ${hostapdPath}`);
        };

        // Ensure systemd unit points to our config so hostapd doesn't exit immediately.
        // Debian typically uses /etc/default/hostapd with DAEMON_CONF="/etc/hostapd/hostapd.conf"
        await sudoExec(`bash -lc 'mkdir -p /etc/default && (test -f /etc/default/hostapd || true) && (grep -q \"^DAEMON_CONF=\" /etc/default/hostapd 2>/dev/null && sed -i \"s|^DAEMON_CONF=.*|DAEMON_CONF=\\\"${hostapdPath}\\\"|\" /etc/default/hostapd || echo \"DAEMON_CONF=\\\"${hostapdPath}\\\"\" >> /etc/default/hostapd)'`);

        if (await hasSystemctl()) {
            // Best effort enable/restart if unit exists
            await sudoExec('systemctl unmask hostapd 2>/dev/null || true');
            await sudoExec('systemctl enable hostapd 2>/dev/null || true');
            try {
                await sudoExec('systemctl restart hostapd');
            } catch (e) {
                // unit not found or access denied -> fallback run directly
                await startHostapdFallback();
            }
        } else {
            await startHostapdFallback();
        }

        console.log('WiFi settings applied successfully.');
        return { success: true, message: 'WiFi settings applied successfully!' };
    } catch (e) {
        console.error('Failed to apply WiFi settings:', e.message);
        throw new Error(`Failed to apply WiFi settings: ${e.message}`);
    }
}



// Bridge LAN + WiFi into br0 and ensure DHCP uses the LAN CIDR.
// Debian-compatible: iproute2 + dnsmasq + hostapd.
async function applyLanBridgeApSettings(config) {
    const {
        lan_interface_name,
        lan_ip_address,
        lan_dns_servers,
        wifi_interface_name
    } = config;

    if (!lan_interface_name || !lan_ip_address) {
        throw new Error('LAN interface name and LAN IP address are required.');
    }

    if (process.platform !== 'linux') {
        console.log('[Simulated] LAN Bridge/AP settings skipped on non-Linux platform.');
        return { success: true, message: 'LAN Bridge/AP settings saved (simulated).' };
    }

    const { ip: gatewayIp, prefix } = parseCidr(lan_ip_address);
    const dhcp = computeDhcpRange(gatewayIp, prefix);

    const wifiIface = wifi_interface_name || detectDefaultWifiInterface();
    const bridge = 'br0';

    try {
        // deps (Debian): dnsmasq may not be installed and service name can differ.
        // We do NOT auto-install packages here; we just configure if present.
        const hasSystemctl = async () => {
            try {
                await execPromise('command -v systemctl');
                return true;
            } catch (e) {
                return false;
            }
        };

        const hasDnsmasq = async () => {
            try {
                // Try multiple checks because `command -v` may fail depending on shell/env.
                await execPromise('dnsmasq --version');
                return true;
            } catch (e1) {
                try {
                    await execPromise('/usr/sbin/dnsmasq --version');
                    return true;
                } catch (e2) {
                    try {
                        await execPromise('which dnsmasq');
                        return true;
                    } catch (e3) {
                        return false;
                    }
                }
            }
        };

        if (!(await hasDnsmasq())) {
            throw new Error('dnsmasq is not installed or not found in PATH. Install it on Debian: sudo apt-get update && sudo apt-get install -y dnsmasq');
        }

        if (await hasSystemctl()) {
            await sudoExec('systemctl unmask dnsmasq 2>/dev/null || true');
            await sudoExec('systemctl enable dnsmasq 2>/dev/null || true');
        }

        // Bring interfaces up (force UP even if NO-CARRIER; required so hostapd can start/broadcast)
        await sudoExec(`ip link set dev ${lan_interface_name} up`);
        await sudoExec(`ip link set dev ${wifiIface} up`);

        // Some drivers need rfkill to be unblocked before AP can broadcast.
        // Your Debian showed `rfkill: command not found`, so this is best-effort.
        await sudoExec('rfkill unblock all 2>/dev/null || true');

        // Prevent conflicts: NetworkManager/wpa_supplicant often blocks AP/bridge operation.
        // Best-effort stop wpa_supplicant and unmanage the interface in NM (if present).
        await sudoExec(`systemctl stop wpa_supplicant 2>/dev/null || true`);
        await sudoExec(`nmcli dev set ${wifiIface} managed no 2>/dev/null || true`);
        await sudoExec(`nmcli dev disconnect ${wifiIface} 2>/dev/null || true`);

        // Ensure WiFi is in managed mode before hostapd takes over (best-effort)
        await sudoExec(`iw dev ${wifiIface} set type managed 2>/dev/null || true`);

        // Create bridge if needed
        await sudoExec(`ip link add name ${bridge} type bridge 2>/dev/null || true`);
        await sudoExec(`ip link set dev ${bridge} up`);

        // Detach IPs from member interfaces
        await sudoExec(`ip addr flush dev ${lan_interface_name} || true`);
        await sudoExec(`ip addr flush dev ${wifiIface} || true`);

        // Add members to bridge (ignore if already added)
        await sudoExec(`ip link set dev ${lan_interface_name} master ${bridge} 2>/dev/null || true`);
        await sudoExec(`ip link set dev ${wifiIface} master ${bridge} 2>/dev/null || true`);

        // Assign gateway IP to bridge (ensure no duplicates)
        await sudoExec(`ip addr flush dev ${bridge} || true`);
        await sudoExec(`ip addr add ${gatewayIp}/${prefix} dev ${bridge}`);

        // dnsmasq config based on CIDR
        const dnsList = (lan_dns_servers && lan_dns_servers.length > 0)
            ? lan_dns_servers
            : ['8.8.8.8', '8.8.4.4'];

const dnsmasqConfig = `
# PisoWiFi captive portal DNS/DHCP on bridge
interface=${bridge}
bind-interfaces
port=53

# DHCP
dhcp-range=${dhcp.start},${dhcp.end},${dhcp.netmask},12h
dhcp-option=3,${gatewayIp}
dhcp-option=6,${gatewayIp}

# Captive portal DNS hijack (force all domains to gateway)
address=/#/${gatewayIp}

# Upstream DNS (used after user is allowed)
server=${dnsList[0]}
${dnsList[1] ? `server=${dnsList[1]}` : ''}

domain-needed
bogus-priv

# IMPORTANT: Captive Portal auto-popup compatibility
# Apple
address=/captive.apple.com/${gatewayIp}
address=/apple.com/${gatewayIp}
address=/gsp1.apple.com/${gatewayIp}
# Android
address=/connectivitycheck.gstatic.com/${gatewayIp}
address=/clients3.google.com/${gatewayIp}
# Windows
address=/www.msftconnecttest.com/${gatewayIp}
address=/dns.msftncsi.com/${gatewayIp}
`.trim() + '\n';

        fs.writeFileSync('/tmp/pisowifi-dnsmasq.conf', dnsmasqConfig);
        await sudoExec('mkdir -p /etc/dnsmasq.d');
        await sudoExec('mv /tmp/pisowifi-dnsmasq.conf /etc/dnsmasq.d/pisowifi.conf');

        // Restart dnsmasq if managed by systemd, otherwise try to start a standalone instance.
        const restartDnsmasq = async () => {
            if (await hasSystemctl()) {
                // If the unit doesn't exist, systemctl will fail; handle below.
                try {
                    await sudoExec('systemctl restart dnsmasq');
                    return;
                } catch (e) {
                    // fallback below
                }
            }

            // Non-systemd / no unit: kill existing dnsmasq then start it with our config directory.
            await sudoExec('pkill dnsmasq 2>/dev/null || true');
            // Prefer absolute path on Debian (often installed under /usr/sbin)
await sudoExec('/usr/sbin/dnsmasq --conf-file=/etc/dnsmasq.conf --conf-dir=/etc/dnsmasq.d || dnsmasq --conf-file=/etc/dnsmasq.conf --conf-dir=/etc/dnsmasq.d');

            // Ensure firewall allows DHCP/DNS to the gateway on LAN bridge
            // If iptables is missing (some minimal/nftables-only images), skip these rules and show an actionable note.
            if (hasIptables()) {
                await sudoExec(`iptables -D INPUT -i ${bridge} -p udp --dport 67 -j ACCEPT || true`);
                await sudoExec(`iptables -D INPUT -i ${bridge} -p udp --dport 53 -j ACCEPT || true`);
                await sudoExec(`iptables -D INPUT -i ${bridge} -p tcp --dport 53 -j ACCEPT || true`);
                await sudoExec(`iptables -I INPUT 1 -i ${bridge} -p udp --dport 67 -j ACCEPT`);
                await sudoExec(`iptables -I INPUT 1 -i ${bridge} -p udp --dport 53 -j ACCEPT`);
                await sudoExec(`iptables -I INPUT 1 -i ${bridge} -p tcp --dport 53 -j ACCEPT`);
            } else {
                console.warn('[Network] iptables not found. Skipping INPUT allow rules for DHCP/DNS on br0. Install it: sudo apt-get update && sudo apt-get install -y iptables');
            }
        };

        await restartDnsmasq();

        // hostapd: bridged mode (bridge=br0)
        // If hostapd isn't installed, don't fail the whole bridge (wired clients can still work).
        const wifiResult = await applyWifiSettings({ ...config, wifi_interface_name: wifiIface });
        if (wifiResult && wifiResult.success === false) {
            return {
                success: true,
                message: `LAN bridge configured (wired OK). WiFi AP skipped: ${wifiResult.message}`
            };
        }

        // Ensure hostapd is bridged. Restart is best-effort (if systemd unit not present we already started hostapd directly).
        await sudoExec(`grep -q "^bridge=${bridge}$" /etc/hostapd/hostapd.conf || echo "bridge=${bridge}" | tee -a /etc/hostapd/hostapd.conf > /dev/null`);
        await sudoExec('systemctl restart hostapd 2>/dev/null || true');

        return {
            success: true,
            message: `LAN bridge/AP configured: bridge=${bridge}, lan=${lan_interface_name}, wifi=${wifiIface}, subnet=${gatewayIp}/${prefix}, dhcp=${dhcp.start}-${dhcp.end}`
        };
    } catch (e) {
        console.error('Failed to apply LAN bridge/AP settings:', e.message);
        throw new Error(`Failed to apply LAN bridge/AP settings: ${e.message}`);
    }
}

// Main function to apply all network settings
async function applyAllNetworkSettings(config) {
    const results = [];

    try {
        // WiFi/hostapd
        // IMPORTANT: include wifi_ssid so changing SSID alone still triggers apply
        if (config.wifi_ssid || config.wifi_password || config.wifi_security || config.wifi_max_users || config.wifi_transmit_power || config.wifi_hidden || config.wifi_interface_name) {
            results.push(await applyWifiSettings(config));
        }

        // Bridge/AP + DHCP based on LAN CIDR
        if (config.lan_interface_name && config.lan_ip_address) {
            results.push(await applyLanBridgeApSettings(config));
        }

        return { success: true, message: 'All network settings applied successfully!', details: results };
    } catch (e) {
        console.error('Failed to apply network settings:', e.message);
        throw new Error(`Failed to apply network settings: ${e.message}`);
    }
}

module.exports = { applyNetworkConfig, applyAllNetworkSettings, applyLanBridgeApSettings, sudoExec };
