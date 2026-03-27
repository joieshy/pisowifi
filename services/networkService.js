const { exec } = require('child_process');
const fs = require('fs');
const util = require('util');
const execPromise = util.promisify(exec);

const SUDO_PASSWORD = process.env.SUDO_PASSWORD || 'Alexjoy-1623';

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


module.exports = { applyNetworkConfig, sudoExec };
