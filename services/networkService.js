const { exec } = require('child_process');
const fs = require('fs');
const util = require('util');
const execPromise = util.promisify(exec);

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
        fs.writeFileSync(tempNetplanPath, netplanConfig);
        await execPromise(`sudo mv ${tempNetplanPath} ${netplanFilePath}`);
        await execPromise(`sudo chmod 600 ${netplanFilePath}`);

        console.log(`Netplan configuration written to ${netplanFilePath}`);
        console.log('Applying Netplan configuration...');
        await execPromise('sudo netplan apply');
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
        await execPromise(`sudo mv /tmp/hostapd.conf ${hostapdPath}`);
        await execPromise(`sudo chmod 600 ${hostapdPath}`);

        // Restart hostapd
        await execPromise('sudo systemctl restart hostapd');
        
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
        await execPromise('sudo mv /tmp/pisowifi-dnsmasq.conf /etc/dnsmasq.d/pisowifi.conf');
        
        // Restart dnsmasq
        await execPromise('sudo systemctl restart dnsmasq');
        
        console.log('DHCP advanced settings applied successfully.');
        return { success: true, message: 'DHCP advanced settings applied successfully!' };
    } catch (e) {
        console.error('Failed to apply DHCP advanced settings:', e.message);
        throw new Error(`Failed to apply DHCP settings: ${e.message}`);
    }
}

// 3. Firewall Settings - Configure DMZ, VPN passthrough, NAT loopback
async function applyFirewallSettings(config) {
    const { dmz_enabled, dmz_ip, vpn_passthrough, nat_loopback, ip_range_start, lan_interface_name, wan_interface_name } = config;

    if (process.platform !== 'linux') {
        console.log('[Simulated] Firewall settings skipped on non-Linux platform.');
        return { success: true, message: 'Firewall settings saved (simulated).' };
    }

    try {
        // Get LAN interface (usually the second interface)
        // Use configured interface or fallback to eth1
        let lanInterface = lan_interface_name || 'eth1';
        let wanInterface = wan_interface_name || 'eth0';

        // Clear existing firewall rules
        await execPromise('sudo iptables -F FORWARD');
        await execPromise('sudo iptables -t nat -F POSTROUTING');

        // DMZ Configuration
        if (dmz_enabled === 'true' && dmz_ip) {
            // Enable IP forwarding
            await execPromise('sudo sysctl -w net.ipv4.ip_forward=1');
            
            // Add DMZ rule - forward all traffic to DMZ IP
            await execPromise(`sudo iptables -A FORWARD -i ${wanInterface} -o ${lanInterface} -d ${dmz_ip} -j ACCEPT`);
            await execPromise(`sudo iptables -t nat -A PREROUTING -i ${wanInterface} -j DNAT --to-destination ${dmz_ip}`);
        }

        // VPN Passthrough
        if (vpn_passthrough === 'true') {
            // Allow PPTP
            await execPromise('sudo iptables -A FORWARD -p gre -j ACCEPT');
            // Allow IPSec
            await execPromise('sudo iptables -A FORWARD -p udp --dport 500 -j ACCEPT');
            await execPromise('sudo iptables -A FORWARD -p udp --dport 4500 -j ACCEPT');
            await execPromise('sudo iptables -A FORWARD -p udp --dport 1701 -j ACCEPT');
            // Allow OpenVPN
            await execPromise('sudo iptables -A FORWARD -i tun+ -j ACCEPT');
            await execPromise('sudo iptables -A FORWARD -o tun+ -j ACCEPT');
        }

        // NAT Loopback (Hairpin NAT)
        if (nat_loopback === 'true') {
            await execPromise(`sudo iptables -t nat -A POSTROUTING -s ${ip_range_start || '10.0.0.0'}/24 -o ${lanInterface} -j MASQUERADE`);
        }

        // Save iptables rules
        await execPromise('sudo iptables-save > /etc/iptables.rules');
        
        console.log('Firewall settings applied successfully.');
        return { success: true, message: 'Firewall settings applied successfully!' };
    } catch (e) {
        console.error('Failed to apply firewall settings:', e.message);
        throw new Error(`Failed to apply firewall settings: ${e.message}`);
    }
}

// 4. WiFi Schedule - Schedule WiFi on/off using cron
async function applyWifiSchedule(config) {
    const { wifi_schedule_enabled, wifi_schedule_start, wifi_schedule_end } = config;

    if (process.platform !== 'linux') {
        console.log('[Simulated] WiFi schedule skipped on non-Linux platform.');
        return { success: true, message: 'WiFi schedule saved (simulated).' };
    }

    try {
        // Remove existing pisowifi schedule cron jobs
        await execPromise('sudo crontab -l 2>/dev/null | grep -v "pisowifi-schedule" | sudo crontab -');

        if (wifi_schedule_enabled === 'true') {
            // Parse time strings (format: HH:MM)
            const [startHour, startMin] = (wifi_schedule_start || '00:00').split(':');
            const [endHour, endMin] = (wifi_schedule_end || '23:59').split(':');

            // Create cron jobs
            // WiFi OFF at start time
            const offCron = `${startMin} ${startHour} * * * sudo systemctl stop hostapd`;
            // WiFi ON at end time
            const onCron = `${endMin} ${endHour} * * * sudo systemctl start hostapd`;

            // Add to crontab
            const currentCrontab = await execPromise('sudo crontab -l 2>/dev/null').catch(() => '');
            const newCrontab = currentCrontab + '\n# PisoWiFi Schedule\n' + offCron + '\n' + onCron + '\n';
            
            fs.writeFileSync('/tmp/pisowifi-cron', newCrontab);
            await execPromise('sudo crontab /tmp/pisowifi-cron');
            
            console.log('WiFi schedule applied successfully.');
            return { success: true, message: 'WiFi schedule applied successfully!' };
        }

        return { success: true, message: 'WiFi schedule disabled.' };
    } catch (e) {
        console.error('Failed to apply WiFi schedule:', e.message);
        throw new Error(`Failed to apply WiFi schedule: ${e.message}`);
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
        await execPromise('sudo mv /tmp/hostapd-advanced.conf /etc/hostapd/hostapd.conf');
        
        // Restart hostapd
        await execPromise('sudo systemctl restart hostapd');
        
        console.log('Wireless advanced settings applied successfully.');
        return { success: true, message: 'Wireless advanced settings applied successfully!' };
    } catch (e) {
        console.error('Failed to apply wireless advanced settings:', e.message);
        throw new Error(`Failed to apply wireless settings: ${e.message}`);
    }
}

// 6. Bandwidth Advanced - Configure traffic shaping with tc (traffic control)
async function applyBandwidthAdvanced(config) {
    const { burst_download, burst_threshold, download_limit, lan_interface_name } = config;

    if (process.platform !== 'linux') {
        console.log('[Simulated] Bandwidth advanced settings skipped on non-Linux platform.');
        return { success: true, message: 'Bandwidth advanced settings saved (simulated).' };
    }

    try {
        const lanInterface = lan_interface_name || 'eth1'; // LAN interface
        
        // Clear existing qdisc rules
        await execPromise(`sudo tc qdisc del dev ${lanInterface} root 2>/dev/null || true`);

        // Convert Mbps to kbit/s (1 Mbps = 1000 kbit/s)
        const downloadRate = download_limit ? Math.round(download_limit * 1000) : 0;
        
        const burstDownload = burst_download ? Math.round(burst_download * 1000) : 0;
        const cburstDownload = burst_threshold ? Math.round(burst_threshold * 1000) : burstDownload;

        if (downloadRate > 0) {
            // Apply download shaping (tc is applied on the interface connected to clients)
            let tcCmd = `sudo tc qdisc add dev ${lanInterface} root handle 1: htb default 10`;
            if (burstDownload > 0 && burstDownload > downloadRate) {
                tcCmd += ` && sudo tc class add dev ${lanInterface} parent 1: classid 1:10 htb rate=${downloadRate}kbit burst=${burstDownload}kbit cburst=${cburstDownload}kbit`;
            } else {
                tcCmd += ` && sudo tc class add dev ${lanInterface} parent 1: classid 1:10 htb rate=${downloadRate}kbit`;
            }
            await execPromise(tcCmd);
        }

        console.log('Bandwidth advanced settings applied successfully.');
        return { success: true, message: 'Bandwidth advanced settings applied successfully!' };
    } catch (e) {
        console.error('Failed to apply bandwidth advanced settings:', e.message);
        throw new Error(`Failed to apply bandwidth settings: ${e.message}`);
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

        if (config.dmz_enabled !== undefined || config.vpn_passthrough !== undefined || config.nat_loopback !== undefined) {
            results.push(await applyFirewallSettings(config));
        }

        if (config.wifi_schedule_enabled !== undefined || config.wifi_schedule_start || config.wifi_schedule_end) {
            results.push(await applyWifiSchedule(config));
        }

        if (config.wifi_isolation !== undefined || config.wifi_beacon_interval || config.wifi_rts_cts || config.wifi_dtIM) {
            results.push(await applyWirelessAdvanced(config));
        }

        if (config.burst_download || config.burst_upload || config.burst_threshold || config.burst_time) {
            results.push(await applyBandwidthAdvanced(config));
        }

        return { success: true, message: 'All network settings applied successfully!', details: results };
    } catch (e) {
        console.error('Failed to apply network settings:', e.message);
        throw new Error(`Failed to apply network settings: ${e.message}`);
    }
}

module.exports = { applyNetworkConfig, applyAllNetworkSettings };
