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
        console.log('[Simulated] Netplan configuration skipped on non-Linux platform.');
        return { success: true, message: 'Network configuration saved (simulated).' };
    }

    try {
        const netplanConfig = generateNetplanConfig(
            wan_interface_name, wan_config_type, wan_ip_address, wan_gateway, wan_dns_servers,
            lan_interface_name, lan_ip_address, lan_dns_servers
        );
        
        const netplanFilePath = `/etc/netplan/01-pisowifi-config.yaml`;

        // Write Netplan config to a temporary file first, then move it
        const tempNetplanPath = `/tmp/01-pisowifi-config.yaml.tmp`;
        
        // Check if /tmp directory exists and is writable
        try {
            fs.writeFileSync(tempNetplanPath, netplanConfig);
            console.log(`Temporary Netplan config written to ${tempNetplanPath}`);
        } catch (writeError) {
            console.error(`Failed to write temporary file: ${writeError.message}`);
            throw new Error(`Failed to write temporary configuration file: ${writeError.message}`);
        }
        
        // Check if file was created
        if (!fs.existsSync(tempNetplanPath)) {
            throw new Error(`Temporary file ${tempNetplanPath} was not created`);
        }
        
        // Ensure /etc/netplan directory exists
        await sudoExec(`mkdir -p /etc/netplan`);
        
        // Use sudoExec helper
        await sudoExec(`mv ${tempNetplanPath} ${netplanFilePath}`);
        await sudoExec(`chmod 600 ${netplanFilePath}`);

        console.log(`Netplan configuration written to ${netplanFilePath}`);
        console.log('Applying Netplan configuration...');
        
        // Use sudoExec helper
        await sudoExec('/usr/sbin/netplan apply');
        
        console.log('Netplan configuration applied successfully.');

        return { success: true, message: 'Network configuration applied successfully!' };
    } catch (e) {
        console.error('Failed to apply Netplan configuration:', e.message);
        throw new Error(`Failed to apply network configuration: ${e.message}`);
    }
}

// ============================================
// NEW NETWORK SETTINGS FUNCTIONS
// ============================================

// 1. WiFi Settings - Configure hostapd for WiFi access point
async function applyWifiSettings(config) {
    const {
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
        // Generate hostapd configuration
        let hostapdConfig = `interface=${wifiIface}
driver=nl80211
ssid=PisoWiFi
country_code=PH
`;

        // Security settings
        if (wifi_security === 'wpa2') {
            hostapdConfig += `hw_mode=g
wpa=2
wpa_passphrase=${wifi_password || 'password'}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
`;
        } else if (wifi_security === 'wpa3') {
            hostapdConfig += `hw_mode=g
wpa=3
wpa_passphrase=${wifi_password || 'password'}
wpa_key_mgmt=SAE
wpa_pairwise=CCMP
rsn_pairwise=CCMP
`;
        } else if (wifi_security === 'wpa2+wpa3') {
            hostapdConfig += `hw_mode=g
wpa=3
wpa_passphrase=${wifi_password || 'password'}
wpa_key_mgmt=SAE WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
`;
        } else {
            // Open network
            hostapdConfig += `hw_mode=g
wpa=0
`;
        }

        // Max users
        if (wifi_max_users) {
            hostapdConfig += `max_num_station=${wifi_max_users}\n`;
        }

        // Transmit power
        if (wifi_transmit_power) {
            hostapdConfig += `txpower=${wifi_transmit_power}\n`;
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

        // Ensure service is enabled (Debian)
        await sudoExec('systemctl unmask hostapd || true');
        await sudoExec('systemctl enable hostapd || true');

        // Restart hostapd
        await sudoExec('systemctl restart hostapd');

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
        // deps (Debian)
        await sudoExec('systemctl unmask dnsmasq || true');
        await sudoExec('systemctl enable dnsmasq || true');

        // Bring interfaces up
        await sudoExec(`ip link set dev ${lan_interface_name} up`);
        await sudoExec(`ip link set dev ${wifiIface} up || true`);

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
interface=${bridge}
dhcp-range=${dhcp.start},${dhcp.end},${dhcp.netmask},12h
dhcp-option=3,${gatewayIp}
dhcp-option=6,${gatewayIp}
address=/#/${gatewayIp}
server=${dnsList[0]}
${dnsList[1] ? `server=${dnsList[1]}` : ''}
bind-interfaces
domain-needed
bogus-priv
`.trim() + '\n';

        fs.writeFileSync('/tmp/pisowifi-dnsmasq.conf', dnsmasqConfig);
        await sudoExec('mkdir -p /etc/dnsmasq.d');
        await sudoExec('mv /tmp/pisowifi-dnsmasq.conf /etc/dnsmasq.d/pisowifi.conf');
        await sudoExec('systemctl restart dnsmasq');

        // hostapd: bridged mode (bridge=br0)
        await applyWifiSettings({ ...config, wifi_interface_name: wifiIface });

        // Ensure hostapd is bridged
        await sudoExec(`grep -q "^bridge=${bridge}$" /etc/hostapd/hostapd.conf || echo "bridge=${bridge}" | tee -a /etc/hostapd/hostapd.conf > /dev/null`);
        await sudoExec('systemctl restart hostapd');

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
        if (config.wifi_password || config.wifi_security || config.wifi_max_users || config.wifi_transmit_power || config.wifi_hidden || config.wifi_interface_name) {
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
