const { exec } = require('child_process');
const fs = require('fs');
const util = require('util');
const execPromise = util.promisify(exec);

const SUDO_PASSWORD = process.env.SUDO_PASSWORD || 'Alexjoy-1623';

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
    const { wifi_password, wifi_security, wifi_max_users, wifi_transmit_power, wifi_hidden, wifi_channel } = config;

    if (process.platform !== 'linux') {
        console.log('[Simulated] WiFi settings skipped on non-Linux platform.');
        return { success: true, message: 'WiFi settings saved (simulated).' };
    }

    try {
        // Generate hostapd configuration
        let hostapdConfig = `interface=wlan0
driver=nl80211
ssid=PisoWiFi
country_code=PH
`;

        // Channel settings
        if (wifi_channel && wifi_channel !== 'auto') {
            hostapdConfig += `channel=${wifi_channel}\n`;
        } else {
            hostapdConfig += `channel=0\n`; // Auto channel
        }

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
        await sudoExec(`mkdir -p /etc/hostapd`);
        
        // Use sudoExec helper
        await sudoExec(`mv /tmp/hostapd.conf ${hostapdPath}`);
        await sudoExec(`chmod 600 ${hostapdPath}`);

        // Restart hostapd
        await sudoExec('systemctl restart hostapd');
        
        console.log('WiFi settings applied successfully.');
        return { success: true, message: 'WiFi settings applied successfully!' };
    } catch (e) {
        console.error('Failed to apply WiFi settings:', e.message);
        throw new Error(`Failed to apply WiFi settings: ${e.message}`);
    }
}

// 2. DHCP Advanced - Configure DHCP lease time in dnsmasq
async function applyDhcpAdvanced(config) {
    const { dhcp_lease_time, ip_range_start, ip_range_end } = config;

    if (process.platform !== 'linux') {
        console.log('[Simulated] DHCP advanced settings skipped on non-Linux platform.');
        return { success: true, message: 'DHCP advanced settings saved (simulated).' };
    }

    try {
        // Read current dnsmasq config
        let dnsmasqConfig = '';
        try {
            dnsmasqConfig = fs.readFileSync('/etc/dnsmasq.d/pisowifi.conf', 'utf8');
        } catch (e) {
            // File doesn't exist, create new config
        }

        // Update DHCP lease time
        if (dhcp_lease_time) {
            // Add or update dhcp-range
            const dhcpRange = `dhcp-range=${ip_range_start || '10.0.0.100'},${ip_range_end || '10.0.0.200'},${dhcp_lease_time}m`;
            
            if (dnsmasqConfig.includes('dhcp-range=')) {
                dnsmasqConfig = dnsmasqConfig.replace(/dhcp-range=.*\n?/g, dhcpRange);
            } else {
                dnsmasqConfig += `\n${dhcpRange}\n`;
            }
        }

        // Write dnsmasq config
        fs.writeFileSync('/tmp/pisowifi-dnsmasq.conf', dnsmasqConfig);
        
        // Ensure /etc/dnsmasq.d directory exists
        await sudoExec('mkdir -p /etc/dnsmasq.d');
        
        // Use sudoExec helper
        await sudoExec('mv /tmp/pisowifi-dnsmasq.conf /etc/dnsmasq.d/pisowifi.conf');
        
        // Restart dnsmasq
        await sudoExec('systemctl restart dnsmasq');
        
        console.log('DHCP advanced settings applied successfully.');
        return { success: true, message: 'DHCP advanced settings applied successfully!' };
    } catch (e) {
        console.error('Failed to apply DHCP advanced settings:', e.message);
        throw new Error(`Failed to apply DHCP settings: ${e.message}`);
    }
}


// 5. Wireless Advanced - Configure advanced wireless settings
async function applyWirelessAdvanced(config) {
    const { wifi_isolation, wifi_beacon_interval, wifi_rts_cts, wifi_dtIM } = config;

    if (process.platform !== 'linux') {
        console.log('[Simulated] Wireless advanced settings skipped on non-Linux platform.');
        return { success: true, message: 'Wireless advanced settings saved (simulated).' };
    }

    try {
        // Read current hostapd config
        let hostapdConfig = '';
        try {
            hostapdConfig = fs.readFileSync('/etc/hostapd/hostapd.conf', 'utf8');
        } catch (e) {}

        // Client Isolation
        if (wifi_isolation === 'true') {
            hostapdConfig += '\nap_isolate=1\n';
        } else {
            hostapdConfig += '\nap_isolate=0\n';
        }

        // Beacon Interval
        if (wifi_beacon_interval) {
            hostapdConfig += `beacon_int=${wifi_beacon_interval}\n`;
        }

        // RTS/CTS Threshold
        if (wifi_rts_cts) {
            hostapdConfig += `rts_threshold=${wifi_rts_cts}\n`;
        }

        // DTIM Interval
        if (wifi_dtIM) {
            hostapdConfig += `dtim_period=${wifi_dtIM}\n`;
        }

        // Write hostapd config
        fs.writeFileSync('/tmp/hostapd-advanced.conf', hostapdConfig);
        
        // Ensure /etc/hostapd directory exists
        await sudoExec('mkdir -p /etc/hostapd');
        
        // Use global sudoExec helper
        await sudoExec('mv /tmp/hostapd-advanced.conf /etc/hostapd/hostapd.conf');
        
        // Restart hostapd
        await sudoExec('systemctl restart hostapd');
        
        console.log('Wireless advanced settings applied successfully.');
        return { success: true, message: 'Wireless advanced settings applied successfully!' };
    } catch (e) {
        console.error('Failed to apply wireless advanced settings:', e.message);
        throw new Error(`Failed to apply wireless settings: ${e.message}`);
    }
}


// Main function to apply all network settings
async function applyAllNetworkSettings(config) {
    const results = [];

    try {
        // Apply each setting category
        if (config.wifi_password || config.wifi_security || config.wifi_max_users || config.wifi_transmit_power || config.wifi_hidden || config.wifi_channel) {
            results.push(await applyWifiSettings(config));
        }

        if (config.dhcp_lease_time || config.ip_range_start || config.ip_range_end) {
            results.push(await applyDhcpAdvanced(config));
        }


        if (config.wifi_isolation !== undefined || config.wifi_beacon_interval || config.wifi_rts_cts || config.wifi_dtIM) {
            results.push(await applyWirelessAdvanced(config));
        }

        return { success: true, message: 'All network settings applied successfully!', details: results };
    } catch (e) {
        console.error('Failed to apply network settings:', e.message);
        throw new Error(`Failed to apply network settings: ${e.message}`);
    }
}

module.exports = { applyNetworkConfig, applyAllNetworkSettings, sudoExec };
