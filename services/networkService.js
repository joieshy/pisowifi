const { exec } = require('child_process');
const fs = require('fs');
const util = require('util');
const os = require('os');
const execPromise = util.promisify(exec);

const SUDO_PASSWORD = process.env.SUDO_PASSWORD || 'Alexjoy-1623';
const interfaceDetector = require('./interfaceDetector');

const DEFAULT_LAN_BRIDGE = 'br0';
const DEFAULT_PORTAL_PORT = 3000;
const DEFAULT_FALLBACK_DNS = ['8.8.8.8', '8.8.4.4'];

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

function normalizeDnsList(dnsServers) {
    if (!Array.isArray(dnsServers) || dnsServers.length === 0) {
        return DEFAULT_FALLBACK_DNS;
    }
    return dnsServers.filter(Boolean);
}

function getInterfaceName(value, fallback) {
    if (!value) return fallback;
    if (typeof value === 'string') return value.trim() || fallback;
    if (typeof value === 'object' && value.name) return value.name;
    return fallback;
}

function getBridgeInterfaceName(config = {}) {
    return getInterfaceName(config.bridge_interface_name || config.bridge_name || config.lan_bridge_name, DEFAULT_LAN_BRIDGE);
}

function getPortalPort(config = {}) {
    const port = Number(config.portal_port || config.app_port || config.port);
    return Number.isFinite(port) && port > 0 ? port : DEFAULT_PORTAL_PORT;
}

/**
 * Check if an IP address is available (no ping response)
 */
async function isIpAvailable(ip) {
    if (process.platform === 'win32') {
        try {
            const { stdout } = await execPromise(`ping -n 1 -w 100 ${ip}`);
            return !stdout.includes('TTL=');
        } catch (e) {
            return true; // Ping failed, likely available
        }
    } else {
        try {
            const { stdout } = await execPromise(`ping -c 1 -W 1 ${ip}`);
            return !stdout.includes('ttl=');
        } catch (e) {
            return true; // Ping failed, likely available
        }
    }
}

/**
 * Find an available IP in the subnet
 */
async function findAvailableIp(networkInt, prefix) {
    const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const networkStart = (networkInt & maskInt) >>> 0;
    const broadcastInt = (networkStart | (~maskInt >>> 0)) >>> 0;
    
    // Start from network + 1, avoid broadcast - 1
    for (let i = 1; i <= 254; i++) {
        const candidate = networkStart + i;
        if (candidate === broadcastInt) continue;
        
        const ip = intToIp(candidate);
        if (await isIpAvailable(ip)) {
            return ip;
        }
    }
    throw new Error('No available IP found in subnet');
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

async function commandExists(command) {
    try {
        await execPromise(`command -v ${command}`);
        return true;
    } catch (e) {
        return false;
    }
}

async function iptablesRuleExists(args) {
    try {
        await sudoExec(`iptables ${args}`);
        return true;
    } catch (e) {
        return false;
    }
}

async function ensureIptablesRule(args, checkArgs) {
    if (!(await iptablesRuleExists(checkArgs))) {
        await sudoExec(`iptables ${args}`);
    }
}

async function applyIptablesRules(wanInterface, lanCidr, options = {}) {
    const lanInterface = getInterfaceName(options.lanInterface || options.lan_interface_name, DEFAULT_LAN_BRIDGE);
    const portalPort = getPortalPort(options);
    const lanIp = lanCidr.split('/')[0];
    const dnsPort = Number(options.dnsPort || 53);

    const forwardCheck = `-C FORWARD -i ${lanInterface} -o ${wanInterface} -j ACCEPT`;
    const forwardAdd = `-A FORWARD -i ${lanInterface} -o ${wanInterface} -j ACCEPT`;
    const returnCheck = `-C FORWARD -i ${wanInterface} -o ${lanInterface} -m state --state ESTABLISHED,RELATED -j ACCEPT`;
    const returnAdd = `-A FORWARD -i ${wanInterface} -o ${lanInterface} -m state --state ESTABLISHED,RELATED -j ACCEPT`;
    const natCheck = `-t nat -C POSTROUTING -s ${lanCidr} -o ${wanInterface} -j MASQUERADE`;
    const natAdd = `-t nat -A POSTROUTING -s ${lanCidr} -o ${wanInterface} -j MASQUERADE`;
    const httpRedirectCheck = `-t nat -C PREROUTING -i ${lanInterface} -p tcp --dport 80 -j REDIRECT --to-ports ${portalPort}`;
    const httpRedirectAdd = `-t nat -A PREROUTING -i ${lanInterface} -p tcp --dport 80 -j REDIRECT --to-ports ${portalPort}`;
    const dnsRedirectCheck = `-t nat -C PREROUTING -i ${lanInterface} -p udp --dport 53 -j REDIRECT --to-ports ${dnsPort}`;
    const dnsRedirectAdd = `-t nat -A PREROUTING -i ${lanInterface} -p udp --dport 53 -j REDIRECT --to-ports ${dnsPort}`;
    const dnsTcpRedirectCheck = `-t nat -C PREROUTING -i ${lanInterface} -p tcp --dport 53 -j REDIRECT --to-ports ${dnsPort}`;
    const dnsTcpRedirectAdd = `-t nat -A PREROUTING -i ${lanInterface} -p tcp --dport 53 -j REDIRECT --to-ports ${dnsPort}`;

    await sudoExec('sysctl -w net.ipv4.ip_forward=1');
    await ensureIptablesRule(forwardAdd, forwardCheck);
    await ensureIptablesRule(returnAdd, returnCheck);
    await ensureIptablesRule(natAdd, natCheck);
    await ensureIptablesRule(httpRedirectAdd, httpRedirectCheck);
    await ensureIptablesRule(dnsRedirectAdd, dnsRedirectCheck);
    await ensureIptablesRule(dnsTcpRedirectAdd, dnsTcpRedirectCheck);

    return { lanInterface, lanIp, portalPort };
}

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
        const wanDnsList = normalizeDnsList(wan_dns_servers);
        const lanDnsList = normalizeDnsList(lan_dns_servers);

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


/**
 * Apply LAN bridge and AP settings with dynamic interface detection
 */
async function applyLanBridgeApSettings(config) {
    const {
        lan_interface_name,
        lan_ip_address,
        lan_dns_servers,
        wan_interface_name
    } = config;

    if (!lan_interface_name || !lan_ip_address) {
        throw new Error('Missing required LAN interface parameters.');
    }

    if (process.platform !== 'linux') {
        console.log('[Simulated] LAN bridge configuration skipped on non-Linux platform.');
        return { success: true, message: 'LAN bridge configuration saved (simulated).' };
    }

    try {
        const bridgeInterface = getBridgeInterfaceName(config);
        const wanInterface = getInterfaceName(wan_interface_name, '');
        const lanDnsList = normalizeDnsList(lan_dns_servers);
        const portalPort = getPortalPort(config);

        // Stop systemd-resolved and lock /etc/resolv.conf to prevent overwrites
        try {
            await sudoExec('systemctl stop systemd-resolved || true');
            await sudoExec('systemctl disable systemd-resolved || true');
            
            const dnsServers = lanDnsList.length > 0 ? lanDnsList : DEFAULT_FALLBACK_DNS;
            const dnsConfig = dnsServers.map(dns => `nameserver ${dns}`).join('\n');
            
            // Remove existing resolv.conf and create new one
            await sudoExec('rm -f /etc/resolv.conf || true');
            await sudoExec(`echo "${dnsConfig}" | tee /etc/resolv.conf > /dev/null`);
            
            // Make /etc/resolv.conf immutable to prevent any service from overwriting it
            await sudoExec('chattr +i /etc/resolv.conf || true');
            
            // Also prevent systemd-resolved from creating its own resolv.conf
            await sudoExec('mkdir -p /run/systemd/resolve || true');
            await sudoExec('touch /run/systemd/resolve/resolv.conf || true');
            await sudoExec('chattr +i /run/systemd/resolve/resolv.conf || true');
            
            console.log(`[Network] DNS configured: ${dnsServers.join(', ')} (locked against overwrites)`);
        } catch (e) {
            console.log('[Network] Note: systemd-resolved handling or DNS configuration failed:', e.message);
        }

        // Create bridge interface
        await sudoExec(`ip link add name ${bridgeInterface} type bridge || true`);
        await sudoExec(`ip link set ${bridgeInterface} up`);
        
        // Add LAN interface to bridge
        await sudoExec(`ip link set ${lan_interface_name} master ${bridgeInterface}`);
        await sudoExec(`ip link set ${lan_interface_name} up`);

        // Configure bridge IP address
        await sudoExec(`ip addr flush dev ${lan_interface_name}`);
        await sudoExec(`ip addr flush dev ${bridgeInterface}`);
        await sudoExec(`ip addr add ${lan_ip_address} dev ${bridgeInterface}`);

        // Enable forwarding for the bridge safely
        await sudoExec('sysctl -w net.ipv4.ip_forward=1');
        await sudoExec(`sysctl -w net.ipv4.conf.${bridgeInterface}.proxy_arp=1 || true`);

        const lanCidr = lan_ip_address;
        const lanIp = lan_ip_address.split('/')[0];
        const dhcpRange = computeDhcpRange(lanIp, parseInt(lan_ip_address.split('/')[1]));
        
        // Use LAN DNS servers for dnsmasq, fallback to Google DNS if none provided
        const dnsServers = lanDnsList.length > 0 ? lanDnsList : DEFAULT_FALLBACK_DNS;
        
        const dnsmasqConfig = `
interface=${bridgeInterface}
bind-interfaces
dhcp-range=${dhcpRange.start},${dhcpRange.end},12h
dhcp-option=option:router,${lanIp}
dhcp-option=option:dns-server,${lanIp}
${dnsServers.map(dns => `server=${dns}`).join('\n')}
no-resolv
log-queries
log-dhcp
`;
        
        fs.writeFileSync('/etc/dnsmasq.conf', dnsmasqConfig);
        await sudoExec('systemctl restart dnsmasq || true');
        await sudoExec('systemctl enable dnsmasq || true');

        if (await commandExists('iptables')) {
            await applyIptablesRules(wanInterface, lanCidr, {
                lanInterface: bridgeInterface,
                portalPort
            });
        }

        console.log('LAN bridge and AP settings applied successfully.');
        return { success: true, message: 'LAN bridge and AP settings applied successfully!', bridge_interface_name: bridgeInterface };
    } catch (e) {
        console.error('Failed to apply LAN bridge configuration:', e.message);
        throw new Error(`Failed to apply LAN bridge configuration: ${e.message}`);
    }
}

/**
 * Get current applied LAN IP and DNS settings
 */
async function getCurrentLanSettings() {
    if (process.platform !== 'linux') {
        return {
            success: true,
            lan_ip: '10.0.0.1/24 (simulated)',
            lan_dns: DEFAULT_FALLBACK_DNS,
            applied: true
        };
    }

    try {
        // Get bridge IP
        const { stdout: ipOutput } = await execPromise(`ip addr show ${DEFAULT_LAN_BRIDGE}`);
        const ipMatch = ipOutput.match(/inet\s+(\d+\.\d+\.\d+\.\d+\/\d+)/);
        const currentLanIp = ipMatch ? ipMatch[1] : 'Not configured';

        // Get DNS servers from resolv.conf
        let currentDns = [];
        try {
            const { stdout: dnsOutput } = await execPromise('cat /etc/resolv.conf');
            const dnsMatches = dnsOutput.match(/nameserver\s+(\d+\.\d+\.\d+\.\d+)/g);
            if (dnsMatches) {
                currentDns = dnsMatches.map(line => line.split(' ')[1]);
            }
        } catch (e) {
            currentDns = DEFAULT_FALLBACK_DNS; // Fallback
        }

        return {
            success: true,
            lan_ip: currentLanIp,
            lan_dns: currentDns,
            applied: currentLanIp !== 'Not configured'
        };
    } catch (e) {
        return {
            success: false,
            error: e.message,
            lan_ip: 'Error',
            lan_dns: [],
            applied: false
        };
    }
}

/**
 * Validate and apply dynamic LAN IP configuration
 */
async function applyDynamicLanIp(config) {
    const { lan_interface_name, desired_subnet, lan_dns_servers } = config;

    if (!lan_interface_name || !desired_subnet) {
        throw new Error('Missing required parameters for dynamic LAN IP configuration.');
    }

    if (process.platform !== 'linux') {
        console.log('[Simulated] Dynamic LAN IP configuration skipped on non-Linux platform.');
        return { 
            success: true, 
            message: 'Dynamic LAN IP configuration saved (simulated).',
            applied_ip: '10.0.0.1/24',
            applied_dns: normalizeDnsList(lan_dns_servers)
        };
    }

    try {
        // Parse desired subnet (e.g., 10.0.0.0/24)
        const subnetMatch = desired_subnet.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
        if (!subnetMatch) {
            throw new Error('Invalid subnet format. Use CIDR notation (e.g., 10.0.0.0/24)');
        }

        const [_, networkIp, prefix] = subnetMatch;
        const networkInt = ipToInt(networkIp);
        const prefixNum = parseInt(prefix);

        // Find an available IP in the subnet
        const availableIp = await findAvailableIp(networkInt, prefixNum);
        const gatewayIp = `${availableIp}/${prefix}`;

        console.log(`[Dynamic LAN] Found available IP: ${availableIp} in subnet ${desired_subnet}`);

        // Apply the configuration
        const result = await applyLanBridgeApSettings({
            lan_interface_name,
            lan_ip_address: gatewayIp,
            lan_dns_servers,
            bridge_interface_name: getBridgeInterfaceName(config),
            wan_interface_name: config.wan_interface_name,
            portal_port: getPortalPort(config)
        });

        return {
            success: true,
            message: `Dynamic LAN IP configuration applied successfully! Gateway: ${gatewayIp}`,
            applied_ip: gatewayIp,
            applied_dns: normalizeDnsList(lan_dns_servers)
        };
    } catch (e) {
        console.error('Failed to apply dynamic LAN IP configuration:', e.message);
        throw new Error(`Failed to apply dynamic LAN IP configuration: ${e.message}`);
    }
}

/**
 * Automatically detect and configure optimal network interfaces
 */
async function autoConfigureNetwork() {
    try {
        if (process.platform !== 'linux') {
            console.log('[Simulated] Auto network configuration skipped on non-Linux platform.');
            return {
                success: true,
                message: 'Auto network configuration completed (simulated).',
                wan: { name: 'eth0', status: 'up', ipAddress: '192.168.1.100', hasInternet: true },
                lan: { name: 'eth1', status: 'up', ipAddress: '10.0.0.1', hasInternet: false }
            };
        }

        // Get recommended configuration
        const config = await interfaceDetector.getRecommendedConfiguration();
        
        if (!config.recommendations.hasInternet) {
            throw new Error('No interface with internet connectivity detected. Please connect your WAN interface to the internet.');
        }

        if (!config.recommendations.hasLanInterface) {
            throw new Error('No suitable LAN interface detected. Please connect a network interface for client connections.');
        }

        // Validate configuration
        const validation = interfaceDetector.validateConfiguration(config.wan, config.lan);
        if (!validation.isValid) {
            throw new Error(`Configuration validation failed: ${validation.errors.join(', ')}`);
        }

        // Apply network configuration
        const networkConfig = {
            wan_interface_name: config.wan.name,
            wan_config_type: 'dhcp', // Auto-detect DHCP for WAN
            wan_ip_address: '',
            wan_gateway: '',
            wan_dns_servers: DEFAULT_FALLBACK_DNS,
            lan_interface_name: config.lan.name,
            lan_ip_address: '10.0.0.1/24', // Default LAN subnet
            lan_dns_servers: DEFAULT_FALLBACK_DNS
        };

        await applyNetworkConfig(networkConfig);
        await applyLanBridgeApSettings({
            ...networkConfig,
            bridge_interface_name: DEFAULT_LAN_BRIDGE,
            portal_port: DEFAULT_PORTAL_PORT
        });

        console.log('Auto network configuration completed successfully.');
        return {
            success: true,
            message: 'Auto network configuration completed successfully!',
            wan: config.wan,
            lan: config.lan,
            configuration: networkConfig
        };
    } catch (error) {
        console.error('Auto network configuration failed:', error.message);
        throw new Error(`Auto network configuration failed: ${error.message}`);
    }
}

/**
 * Get current network status and interface information
 */
async function getNetworkStatus() {
    try {
        const interfaces = await interfaceDetector.getAllInterfaces();
        const wanInterface = await interfaceDetector.detectWanInterface();
        const lanInterface = await interfaceDetector.detectLanInterface();
        
        return {
            interfaces,
            wan: wanInterface,
            lan: lanInterface,
            hasInternet: !!wanInterface,
            hasLanInterface: !!lanInterface,
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        console.error('Failed to get network status:', error.message);
        return {
            interfaces: [],
            wan: null,
            lan: null,
            hasInternet: false,
            hasLanInterface: false,
            error: error.message
        };
    }
}

module.exports = { 
    applyNetworkConfig, 
    sudoExec, 
    applyLanBridgeApSettings, 
    autoConfigureNetwork, 
    getNetworkStatus,
    getCurrentLanSettings,
    applyDynamicLanIp,
    applyIptablesRules,
    getBridgeInterfaceName,
    getPortalPort
};