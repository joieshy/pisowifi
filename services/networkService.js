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

let cachedDb = null;
let cachedSettingsStore = null;
let cachedStateFile = null;

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
    if (typeof dnsServers === 'string') {
        dnsServers = dnsServers.split(',');
    }
    if (!Array.isArray(dnsServers) || dnsServers.length === 0) {
        return DEFAULT_FALLBACK_DNS;
    }
    return [...new Set(dnsServers.filter(Boolean).map(dns => String(dns).trim()).filter(Boolean))];
}

function getInterfaceName(value, fallback) {
    if (!value) return fallback;
    if (typeof value === 'string') return value.trim() || fallback;
    if (typeof value === 'object' && value.name) return value.name;
    return fallback;
}

function getBridgeInterfaceName(config = {}) {
    return getInterfaceName(config.bridge_interface_name || config.bridge_name || config.lan_bridge_name || config.lan_interface_name, DEFAULT_LAN_BRIDGE);
}

function getPortalPort(config = {}) {
    const port = Number(config.portal_port || config.app_port || config.port);
    return Number.isFinite(port) && port > 0 ? port : DEFAULT_PORTAL_PORT;
}

function buildDnsmasqConfig(bridgeInterface, lanIp, dhcpRange, lanDnsServers) {
    const upstreamDns = normalizeDnsList(lanDnsServers);
    const lines = [
        `interface=${bridgeInterface}`,
        'bind-interfaces',
        `dhcp-range=${dhcpRange.start},${dhcpRange.end},12h`,
        `dhcp-option=option:router,${lanIp}`,
        `dhcp-option=option:dns-server,${lanIp}`,
        ...upstreamDns.map(dns => `server=${dns}`),
        'no-resolv',
        'log-queries',
        'log-dhcp'
    ];
    return `${[...new Set(lines)].join('\n')}\n`;
}

function readDnsmasqConfig(pathname) {
    try {
        if (!fs.existsSync(pathname)) return '';
        return fs.readFileSync(pathname, 'utf8');
    } catch (e) {
        return '';
    }
}

function writeIfChanged(pathname, content) {
    const existing = readDnsmasqConfig(pathname);
    if (existing === content) return false;
    fs.writeFileSync(pathname, content);
    return true;
}

async function isIpAvailable(ip) {
    if (process.platform === 'win32') {
        try {
            const { stdout } = await execPromise(`ping -n 1 -w 100 ${ip}`);
            return !stdout.includes('TTL=');
        } catch (e) {
            return true;
        }
    } else {
        try {
            const { stdout } = await execPromise(`ping -c 1 -W 1 ${ip}`);
            return !stdout.toLowerCase().includes('ttl=');
        } catch (e) {
            return true;
        }
    }
}

async function findAvailableIp(networkInt, prefix) {
    const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const networkStart = (networkInt & maskInt) >>> 0;
    const broadcastInt = (networkStart | (~maskInt >>> 0)) >>> 0;

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

function computeDhcpRange(gatewayIp, prefix) {
    const gwInt = ipToInt(gatewayIp);
    const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const networkInt = (gwInt & maskInt) >>> 0;
    const broadcastInt = (networkInt | (~maskInt >>> 0)) >>> 0;

    const firstUsable = networkInt + 1;
    const lastUsable = broadcastInt - 1;

    let start = networkInt + 10;
    if (start < firstUsable) start = firstUsable;
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

async function commandExists(command) {
    try {
        await execPromise(`command -v ${command}`);
        return true;
    } catch (e) {
        return false;
    }
}

async function sudoExec(command) {
    try {
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

function normalizeSettingsSource(source = {}) {
    const settings = source.settings && typeof source.settings === 'object' ? source.settings : source;
    const rows = source.rows || source.data || [];
    return { settings, rows };
}

function normalizeDbRowsToSettings(rows) {
    const settings = {};
    if (!Array.isArray(rows)) return settings;

    for (const row of rows) {
        if (!row || typeof row !== 'object') continue;
        const key = row.setting_key || row.key || row.name;
        if (!key) continue;
        const value = Object.prototype.hasOwnProperty.call(row, 'setting_value')
            ? row.setting_value
            : Object.prototype.hasOwnProperty.call(row, 'value')
                ? row.value
                : row.data;
        settings[key] = value;
    }

    return settings;
}

function parseStoredDns(value) {
    if (Array.isArray(value)) return normalizeDnsList(value);
    if (typeof value === 'string') {
        return normalizeDnsList(value.split(','));
    }
    return [];
}

function resolveNetworkSettings(input = {}) {
    const { settings, rows } = normalizeSettingsSource(input);
    const rowSettings = normalizeDbRowsToSettings(rows);
    const merged = { ...rowSettings, ...settings };

    const wan_interface_name = getInterfaceName(
        merged.wan_interface_name || merged.wan_interface || merged.wan_ifname || merged.wanInterface,
        ''
    );
    const lan_interface_name = getInterfaceName(
        merged.lan_interface_name || merged.lan_interface || merged.lan_ifname || merged.lanInterface || merged.bridge_interface_name,
        DEFAULT_LAN_BRIDGE
    );
    const lan_ip_address = merged.lan_ip_address || merged.lan_ip || merged.gateway_ip || '';
    const wan_dns_servers = parseStoredDns(merged.wan_dns_servers || merged.wan_dns || merged.dns_servers);
    const lan_dns_servers = parseStoredDns(merged.lan_dns_servers || merged.lan_dns || merged.dns_servers);
    const wan_config_type = merged.wan_config_type || merged.wan_mode || 'dhcp';
    const wan_ip_address = merged.wan_ip_address || merged.wan_ip || '';
    const wan_gateway = merged.wan_gateway || merged.gateway || '';
    const desired_subnet = merged.desired_subnet || merged.lan_subnet || '';
    const bridge_interface_name = getBridgeInterfaceName(merged);
    const portal_port = getPortalPort(merged);

    return {
        ...merged,
        wan_interface_name,
        lan_interface_name,
        lan_ip_address,
        wan_dns_servers,
        lan_dns_servers,
        wan_config_type,
        wan_ip_address,
        wan_gateway,
        desired_subnet,
        bridge_interface_name,
        portal_port
    };
}

function setNetworkDataSource(source) {
    if (source && typeof source === 'object') {
        if (source.db || source.sqliteDb) {
            cachedDb = source.db || source.sqliteDb;
        }
        if (source.settingsStore) {
            cachedSettingsStore = source.settingsStore;
        }
        if (source.stateFile) {
            cachedStateFile = source.stateFile;
        }
    }
}

function getRuntimeStateFile() {
    return cachedStateFile || process.env.PISOWIFI_NETWORK_STATE_FILE || path.join(process.cwd(), 'network-state.json');
}

function readRuntimeState() {
    try {
        const stateFile = getRuntimeStateFile();
        if (!fs.existsSync(stateFile)) return {};
        const raw = fs.readFileSync(stateFile, 'utf8');
        return raw ? JSON.parse(raw) : {};
    } catch (e) {
        return {};
    }
}

function writeRuntimeState(state = {}) {
    try {
        const stateFile = getRuntimeStateFile();
        fs.writeFileSync(stateFile, JSON.stringify(state, null, 2));
        return stateFile;
    } catch (e) {
        return null;
    }
}

async function loadNetworkSettings(source = {}) {
    setNetworkDataSource(source);

    const direct = resolveNetworkSettings(source);
    const hasSavedValues = !!(direct.wan_interface_name || direct.lan_interface_name || direct.lan_ip_address || direct.wan_gateway || (direct.wan_dns_servers && direct.wan_dns_servers.length) || (direct.lan_dns_servers && direct.lan_dns_servers.length));

    if (hasSavedValues) {
        return direct;
    }

    if (cachedSettingsStore && typeof cachedSettingsStore.getAll === 'function') {
        const storeSettings = await cachedSettingsStore.getAll();
        return resolveNetworkSettings({ settings: storeSettings });
    }

    if (cachedDb && typeof cachedDb.all === 'function') {
        const rows = await new Promise((resolve, reject) => {
            cachedDb.all('SELECT key, value FROM settings', [], (err, result) => {
                if (err) return reject(err);
                resolve(result || []);
            });
        });
        return resolveNetworkSettings({ rows });
    }

    return direct;
}

async function applyIptablesRules(wanInterface, lanCidr, options = {}) {
    if (!wanInterface || !lanCidr) {
        throw new Error('WAN interface and LAN CIDR are required for iptables rules.');
    }

    const lanInterface = getInterfaceName(options.lanInterface || options.lan_interface_name || options.bridge_interface_name || options.bridge_name, DEFAULT_LAN_BRIDGE);
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

function generateNetplanConfig(wanInterface, wanConfigType, wanIp, wanGateway, wanDns, lanInterface, lanIp, lanDns) {
    let config = `network:
  version: 2
  renderer: networkd
  ethernets:
`;

    config += `    ${wanInterface}:\n`;
    if (wanConfigType === 'dhcp') {
        config += `      dhcp4: true\n`;
    } else {
        config += `      dhcp4: false\n`;
        config += `      addresses: [${wanIp}]\n`;
        if (wanGateway) {
            config += `      gateway4: ${wanGateway}\n`;
        }
        if (wanDns && wanDns.length > 0) {
            config += `      nameservers:\n        addresses: [${wanDns.join(', ')}]\n`;
        }
    }
    config += `      optional: true\n`;

    config += `    ${lanInterface}:\n`;
    config += `      dhcp4: false\n`;
    config += `      addresses: [${lanIp}]\n`;
    if (lanDns && lanDns.length > 0) {
        config += `      nameservers:\n        addresses: [${lanDns.join(', ')}]\n`;
    }

    return config;
}

async function applyNetworkConfig(config) {
    const resolved = await loadNetworkSettings(config);
    const {
        wan_interface_name, wan_config_type, wan_ip_address, wan_gateway, wan_dns_servers,
        lan_interface_name, lan_ip_address, lan_dns_servers
    } = resolved;

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
                wan_interface_name, wan_config_type, wan_ip_address, wan_gateway, normalizeDnsList(wan_dns_servers),
                lan_interface_name, lan_ip_address, normalizeDnsList(lan_dns_servers)
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

        const interfacesPath = '/etc/network/interfaces';
        const wanDnsList = normalizeDnsList(wan_dns_servers);
        const lanDnsList = normalizeDnsList(lan_dns_servers);

        const lines = [];
        lines.push('# Generated by PisoWiFi');
        lines.push('auto lo');
        lines.push('iface lo inet loopback');
        lines.push('');

        lines.push(`auto ${wan_interface_name}`);
        if (wan_config_type === 'dhcp') {
            lines.push(`iface ${wan_interface_name} inet dhcp`);
        } else {
            lines.push(`iface ${wan_interface_name} inet static`);
            if (wan_ip_address) lines.push(`  address ${wan_ip_address.split('/')[0]}`);
            if (wan_ip_address && wan_ip_address.includes('/')) {
                const { prefix } = parseCidr(wan_ip_address);
                lines.push(`  netmask ${cidrToMask(prefix)}`);
            }
            if (wan_gateway) lines.push(`  gateway ${wan_gateway}`);
            if (wanDnsList.length > 0) lines.push(`  dns-nameservers ${wanDnsList.join(' ')}`);
        }
        lines.push('');

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

async function writeResolvConf(dnsServers) {
    const dnsList = normalizeDnsList(dnsServers);
    const dnsConfig = `${dnsList.map(dns => `nameserver ${dns}`).join('\n')}\n`;
    const tempPath = '/tmp/pisowifi-resolv.conf';

    fs.writeFileSync(tempPath, dnsConfig);
    await sudoExec('mkdir -p /etc');
    await sudoExec('chattr -i /etc/resolv.conf 2>/dev/null || true');
    await sudoExec(`cp ${tempPath} /etc/resolv.conf`);
    await sudoExec('chmod 644 /etc/resolv.conf 2>/dev/null || true');
    await sudoExec('rm -f /run/systemd/resolve/resolv.conf 2>/dev/null || true');
    await sudoExec('mkdir -p /run/systemd/resolve 2>/dev/null || true');
    await sudoExec(`cp ${tempPath} /run/systemd/resolve/resolv.conf 2>/dev/null || true`);
}

async function applyLanBridgeApSettings(config) {
    const resolved = await loadNetworkSettings(config);
    const {
        lan_interface_name,
        lan_ip_address,
        lan_dns_servers,
        wan_interface_name
    } = resolved;

    if (!lan_interface_name || !lan_ip_address) {
        throw new Error('Missing required LAN interface parameters.');
    }

    if (process.platform !== 'linux') {
        console.log('[Simulated] LAN bridge configuration skipped on non-Linux platform.');
        return { success: true, message: 'LAN bridge configuration saved (simulated).' };
    }

    try {
        const bridgeInterface = getBridgeInterfaceName({
            ...resolved,
            bridge_interface_name: resolved.bridge_interface_name || lan_interface_name
        });
        const wanInterface = getInterfaceName(wan_interface_name, '');
        const lanDnsList = normalizeDnsList(lan_dns_servers);
        const portalPort = getPortalPort(resolved);
        const lanCidr = lan_ip_address;
        const { ip: lanIp, prefix } = parseCidr(lan_ip_address);

        try {
            await sudoExec('systemctl stop systemd-resolved || true');
            await sudoExec('systemctl disable systemd-resolved || true');
            await writeResolvConf(lanDnsList.length > 0 ? lanDnsList : DEFAULT_FALLBACK_DNS);
            console.log(`[Network] DNS configured: ${(lanDnsList.length > 0 ? lanDnsList : DEFAULT_FALLBACK_DNS).join(', ')}`);
        } catch (e) {
            console.log('[Network] Note: DNS configuration failed:', e.message);
        }

        await sudoExec(`ip link add name ${bridgeInterface} type bridge 2>/dev/null || true`);
        await sudoExec(`ip link set ${bridgeInterface} up`);
        await sudoExec(`ip link set ${lan_interface_name} master ${bridgeInterface} 2>/dev/null || true`);
        await sudoExec(`ip link set ${lan_interface_name} up`);
        await sudoExec(`ip addr flush dev ${lan_interface_name} 2>/dev/null || true`);
        await sudoExec(`ip addr flush dev ${bridgeInterface} 2>/dev/null || true`);
        await sudoExec(`ip addr add ${lan_ip_address} dev ${bridgeInterface}`);

        await sudoExec('sysctl -w net.ipv4.ip_forward=1');
        await sudoExec(`sysctl -w net.ipv4.conf.${bridgeInterface}.proxy_arp=1 || true`);

        const dhcpRange = computeDhcpRange(lanIp, prefix);
        const dnsmasqConfig = buildDnsmasqConfig(bridgeInterface, lanIp, dhcpRange, lanDnsList);

        const dnsmasqPath = '/etc/dnsmasq.conf';
        const dnsmasqUpdated = writeIfChanged(dnsmasqPath, dnsmasqConfig);
        if (dnsmasqUpdated) {
            const tempDnsmasqPath = '/tmp/dnsmasq.conf';
            fs.writeFileSync(tempDnsmasqPath, dnsmasqConfig);
            await sudoExec(`mv ${tempDnsmasqPath} ${dnsmasqPath}`);
        }
        await sudoExec('systemctl enable dnsmasq || true');
        await sudoExec('systemctl restart dnsmasq || true');
        if (!dnsmasqUpdated) {
            console.log('[Network] dnsmasq configuration already up to date.');
        }

        if (await commandExists('iptables')) {
            await applyIptablesRules(wanInterface, lanCidr, {
                lanInterface: bridgeInterface,
                bridge_interface_name: bridgeInterface,
                portalPort,
                dnsPort: 53
            });
        }

        console.log('LAN bridge and AP settings applied successfully.');
        return { success: true, message: 'LAN bridge and AP settings applied successfully!', bridge_interface_name: bridgeInterface };
    } catch (e) {
        console.error('Failed to apply LAN bridge configuration:', e.message);
        throw new Error(`Failed to apply LAN bridge configuration: ${e.message}`);
    }
}

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
        const { stdout: ipOutput } = await execPromise(`ip addr show ${DEFAULT_LAN_BRIDGE}`);
        const ipMatch = ipOutput.match(/inet\s+(\d+\.\d+\.\d+\.\d+\/\d+)/);
        const currentLanIp = ipMatch ? ipMatch[1] : 'Not configured';

        let currentDns = [];
        try {
            const { stdout: dnsOutput } = await execPromise('cat /etc/resolv.conf');
            const dnsMatches = dnsOutput.match(/nameserver\s+(\d+\.\d+\.\d+\.\d+)/g);
            if (dnsMatches) {
                currentDns = dnsMatches.map(line => line.split(' ')[1]);
            }
        } catch (e) {
            currentDns = DEFAULT_FALLBACK_DNS;
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

async function applyDynamicLanIp(config) {
    const resolved = await loadNetworkSettings(config);
    const { lan_interface_name, desired_subnet, lan_dns_servers } = resolved;

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
        const subnetMatch = desired_subnet.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
        if (!subnetMatch) {
            throw new Error('Invalid subnet format. Use CIDR notation (e.g., 10.0.0.0/24)');
        }

        const [_, networkIp, prefix] = subnetMatch;
        const networkInt = ipToInt(networkIp);
        const prefixNum = parseInt(prefix, 10);

        const availableIp = await findAvailableIp(networkInt, prefixNum);
        const gatewayIp = `${availableIp}/${prefix}`;

        console.log(`[Dynamic LAN] Found available IP: ${availableIp} in subnet ${desired_subnet}`);

        await applyLanBridgeApSettings({
            ...resolved,
            lan_interface_name,
            lan_ip_address: gatewayIp,
            lan_dns_servers,
            bridge_interface_name: getBridgeInterfaceName(resolved),
            wan_interface_name: resolved.wan_interface_name,
            portal_port: getPortalPort(resolved)
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

        const config = await interfaceDetector.getRecommendedConfiguration();

        if (!config || !config.recommendations || !config.recommendations.hasInternet) {
            throw new Error('No interface with internet connectivity detected. Please connect your WAN interface to the internet.');
        }

        if (!config.recommendations.hasLanInterface) {
            throw new Error('No suitable LAN interface detected. Please connect a network interface for client connections.');
        }

        const validation = interfaceDetector.validateConfiguration(config.wan, config.lan);
        if (!validation.isValid) {
            throw new Error(`Configuration validation failed: ${validation.errors.join(', ')}`);
        }

        const networkConfig = resolveNetworkSettings({
            wan_interface_name: config.wan.name,
            wan_config_type: 'dhcp',
            wan_ip_address: '',
            wan_gateway: '',
            wan_dns_servers: DEFAULT_FALLBACK_DNS,
            lan_interface_name: config.lan.name,
            lan_ip_address: '10.0.0.1/24',
            lan_dns_servers: DEFAULT_FALLBACK_DNS,
            bridge_interface_name: DEFAULT_LAN_BRIDGE,
            portal_port: DEFAULT_PORTAL_PORT
        });

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

async function getNetworkStatus() {
    try {
        const interfaces = await interfaceDetector.getAllInterfaces();
        const wanInterface = await interfaceDetector.detectWanInterface();
        const lanInterface = await interfaceDetector.detectLanInterface();

        return {
            interfaces: Array.isArray(interfaces) ? interfaces : [],
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

async function restoreSavedNetworkSettings(source = {}) {
    const runtimeState = readRuntimeState();
    const resolved = await loadNetworkSettings(source);

    const merged = resolveNetworkSettings({
        ...runtimeState,
        ...resolved
    });

    if (!merged.wan_interface_name || !merged.lan_interface_name || !merged.lan_ip_address) {
        throw new Error('Saved network settings are incomplete. WAN interface, LAN interface, and LAN IP are required.');
    }

    await applyLanBridgeApSettings(merged);
    await reapplyRuntimeFirewall(merged);

    return {
        success: true,
        message: 'Saved network settings restored successfully.',
        settings: merged
    };
}

async function reapplyRuntimeFirewall(settings = {}) {
    if (process.platform !== 'linux') return;
    const resolved = resolveNetworkSettings(settings);
    if (!resolved.wan_interface_name || !resolved.lan_ip_address) return;
    await applyIptablesRules(resolved.wan_interface_name, resolved.lan_ip_address, {
        lanInterface: resolved.bridge_interface_name,
        bridge_interface_name: resolved.bridge_interface_name,
        portalPort: resolved.portal_port,
        dnsPort: 53
    });
}

async function allowWanToLanInternet(settings = {}) {
    if (process.platform !== 'linux') return { success: true, message: 'Internet allowed from WAN to LAN (simulated).' };

    const resolved = resolveNetworkSettings(settings);
    const wanInterface = getInterfaceName(resolved.wan_interface_name, 'eth0');
    const lanInterface = getInterfaceName(resolved.lan_interface_name || resolved.bridge_interface_name, 'eth1');

    await sudoExec('sysctl -w net.ipv4.ip_forward=1');
    await sudoExec(`sysctl -w net.ipv4.conf.${wanInterface}.forwarding=1 || true`);
    await sudoExec(`sysctl -w net.ipv4.conf.${lanInterface}.forwarding=1 || true`);

    await sudoExec(`iptables -t nat -C POSTROUTING -o ${wanInterface} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${wanInterface} -j MASQUERADE`);

    await sudoExec(`iptables -C FORWARD -i ${lanInterface} -o ${wanInterface} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${lanInterface} -o ${wanInterface} -j ACCEPT`);
    await sudoExec(`iptables -C FORWARD -i ${wanInterface} -o ${lanInterface} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${wanInterface} -o ${lanInterface} -m state --state RELATED,ESTABLISHED -j ACCEPT`);

    return {
        success: true,
        message: `Linux/Debian forwarding enabled: ${wanInterface} -> ${lanInterface}`
    };
}

async function persistRuntimeNetworkSettings(settings = {}) {
    const resolved = resolveNetworkSettings(settings);
    writeRuntimeState({
        ...resolved,
        lastSavedAt: new Date().toISOString()
    });
    return resolved;
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
    getPortalPort,
    loadNetworkSettings,
    resolveNetworkSettings,
    setNetworkDataSource,
    restoreSavedNetworkSettings,
    persistRuntimeNetworkSettings,
    reapplyRuntimeFirewall,
    allowWanToLanInternet,
    readRuntimeState,
    writeRuntimeState
};
