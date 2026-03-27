const { execSync, exec } = require('child_process');
const util = require('util');
const os = require('os');

const execPromise = util.promisify(exec);

/**
 * Interface Detection and Management System
 * Automatically detects and manages network interfaces for dynamic configuration
 */

class InterfaceDetector {
    constructor() {
        this.cachedInterfaces = null;
        this.cacheTimeout = 5000;
        this.lastCacheTime = 0;
    }

    async getAllInterfaces() {
        const now = Date.now();
        if (this.cachedInterfaces && (now - this.lastCacheTime) < this.cacheTimeout) {
            return this.cachedInterfaces;
        }

        try {
            if (os.platform() === 'linux') {
                const output = execSync('ls /sys/class/net', { encoding: 'utf8' });
                const interfaceNames = output.split('\n').map(name => name.trim()).filter(name => name && name !== 'lo');

                const interfaces = await Promise.all(
                    interfaceNames.map(async (name) => {
                        return await this.getInterfaceDetails(name);
                    })
                );

                this.cachedInterfaces = interfaces.filter(iface => iface !== null);
                this.lastCacheTime = now;
                return this.cachedInterfaces;
            } else if (os.platform() === 'win32') {
                const output = execSync('powershell -Command "Get-NetAdapter | Where-Object {$_.Status -ne \'Disabled\'} | Select-Object -ExpandProperty Name"', { encoding: 'utf8' });
                const interfaceNames = output.split('\n').map(name => name.trim()).filter(name => name);

                const interfaces = await Promise.all(
                    interfaceNames.map(async (name) => {
                        return await this.getWindowsInterfaceDetails(name);
                    })
                );

                this.cachedInterfaces = interfaces.filter(iface => iface !== null);
                this.lastCacheTime = now;
                return this.cachedInterfaces;
            } else {
                return [];
            }
        } catch (error) {
            console.error('Error getting interfaces:', error.message);
            return [];
        }
    }

    async getInterfaceDetails(interfaceName) {
        try {
            const details = {
                name: interfaceName,
                status: 'unknown',
                ipAddress: null,
                macAddress: null,
                speed: null,
                hasInternet: false,
                isWireless: false,
                isVirtual: false
            };

            try {
                const operstate = execSync(`cat /sys/class/net/${interfaceName}/operstate`, { encoding: 'utf8' }).trim();
                details.status = operstate === 'up' ? 'up' : 'down';
            } catch (e) {
                details.status = 'down';
            }

            try {
                const mac = execSync(`cat /sys/class/net/${interfaceName}/address`, { encoding: 'utf8' }).trim();
                details.macAddress = mac.toUpperCase();
            } catch (e) {
            }

            try {
                const ipOutput = execSync(`ip -4 addr show ${interfaceName}`, { encoding: 'utf8' });
                const ipMatch = ipOutput.match(/inet\s+(\d+\.\d+\.\d+\.\d+)/);
                if (ipMatch) {
                    details.ipAddress = ipMatch[1];
                }
            } catch (e) {
            }

            try {
                execSync(`test -d /sys/class/net/${interfaceName}/wireless`, { stdio: 'ignore' });
                details.isWireless = true;
            } catch (e) {
                details.isWireless = false;
            }

            try {
                const type = execSync(`cat /sys/class/net/${interfaceName}/type`, { encoding: 'utf8' }).trim();
                details.isVirtual = type === '772';
            } catch (e) {
                details.isVirtual = false;
            }

            if (details.status === 'up' && details.ipAddress) {
                details.hasInternet = await this.testInternetConnectivity(interfaceName);
            }

            return details;
        } catch (error) {
            console.error(`Error getting details for ${interfaceName}:`, error.message);
            return null;
        }
    }

    async getWindowsInterfaceDetails(interfaceName) {
        try {
            const details = {
                name: interfaceName,
                status: 'unknown',
                ipAddress: null,
                macAddress: null,
                speed: null,
                hasInternet: false,
                isWireless: false,
                isVirtual: false
            };

            const psCommand = `
                $adapter = Get-NetAdapter -Name "${interfaceName}" -ErrorAction SilentlyContinue
                if ($adapter) {
                    $status = $adapter.Status
                    $mac = $adapter.MacAddress
                    $ipv4 = (Get-NetIPAddress -InterfaceAlias "${interfaceName}" -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
                    $isWireless = $adapter.InterfaceDescription -match "Wireless|Wi-Fi|802.11"
                    $isVirtual = $adapter.InterfaceDescription -match "Virtual|VMware|VirtualBox|Hyper-V"
                    Write-Output "STATUS:$status"
                    Write-Output "MAC:$mac"
                    Write-Output "IP:$ipv4"
                    Write-Output "WIRELESS:$isWireless"
                    Write-Output "VIRTUAL:$isVirtual"
                }
            `;

            const output = execSync(`powershell -Command "${psCommand}"`, { encoding: 'utf8' });

            const lines = output.split('\n');
            lines.forEach(line => {
                const [key, value] = line.split(':');
                if (key && value) {
                    switch (key.trim()) {
                        case 'STATUS':
                            details.status = value.trim().toLowerCase();
                            break;
                        case 'MAC':
                            details.macAddress = value.trim().toUpperCase();
                            break;
                        case 'IP':
                            details.ipAddress = value.trim();
                            break;
                        case 'WIRELESS':
                            details.isWireless = value.trim().toLowerCase() === 'true';
                            break;
                        case 'VIRTUAL':
                            details.isVirtual = value.trim().toLowerCase() === 'true';
                            break;
                    }
                }
            });

            if (details.status === 'up' && details.ipAddress) {
                details.hasInternet = await this.testInternetConnectivity(interfaceName);
            }

            return details;
        } catch (error) {
            console.error(`Error getting Windows interface details for ${interfaceName}:`, error.message);
            return null;
        }
    }

    async testInternetConnectivity(interfaceName) {
        try {
            if (os.platform() === 'linux') {
                try {
                    const result = await execPromise(
                        `sudo timeout 5 ping -I ${interfaceName} -c 2 8.8.8.8`,
                        { timeout: 6000 }
                    );
                    return result.stdout.includes('2 packets transmitted, 2 received') ||
                           result.stdout.includes('2 packets transmitted, 1 received');
                } catch (sudoError) {
                    try {
                        const result = await execPromise(
                            `timeout 5 ping -I ${interfaceName} -c 2 8.8.8.8`,
                            { timeout: 6000 }
                        );
                        return result.stdout.includes('2 packets transmitted, 2 received') ||
                               result.stdout.includes('2 packets transmitted, 1 received');
                    } catch (regularError) {
                        return await this.checkConnectivityAlternative(interfaceName);
                    }
                }
            } else if (os.platform() === 'win32') {
                const result = await execPromise(
                    `ping -n 2 -w 3000 8.8.8.8`,
                    { timeout: 6000 }
                );
                return result.stdout.includes('TTL=');
            }
            return false;
        } catch (error) {
            return false;
        }
    }

    async checkConnectivityAlternative(interfaceName) {
        try {
            try {
                const result = await execPromise(
                    `curl --interface ${interfaceName} --connect-timeout 5 --head https://8.8.8.8`,
                    { timeout: 6000 }
                );
                return typeof result.stdout === 'string' && result.stdout.length >= 0;
            } catch (curlError) {
                try {
                    const result = await execPromise(
                        `wget --timeout=5 --spider --bind-address=${interfaceName} https://8.8.8.8`,
                        { timeout: 6000 }
                    );
                    return typeof result.stdout === 'string' && result.stdout.length >= 0;
                } catch (wgetError) {
                    const result = await execPromise(
                        `nslookup google.com 8.8.8.8`,
                        { timeout: 6000 }
                    );
                    return result.stdout.includes('Name:') || result.stdout.includes('Address:');
                }
            }
        } catch (e) {
            return false;
        }
    }

    async detectWanInterface() {
        const interfaces = await this.getAllInterfaces();

        const wanCandidates = interfaces.filter(iface =>
            iface.status === 'up' &&
            iface.ipAddress &&
            iface.hasInternet &&
            !iface.isVirtual &&
            !iface.name.startsWith('br') &&
            iface.name !== 'lo'
        );

        if (wanCandidates.length > 0) {
            return wanCandidates[0];
        }

        const wirelessWanCandidates = interfaces.filter(iface =>
            iface.status === 'up' &&
            iface.ipAddress &&
            iface.hasInternet &&
            !iface.isVirtual &&
            iface.isWireless
        );

        if (wirelessWanCandidates.length > 0) {
            return wirelessWanCandidates[0];
        }

        const anyInternetInterface = interfaces.find(iface =>
            iface.status === 'up' &&
            iface.ipAddress &&
            iface.hasInternet &&
            !iface.name.startsWith('br')
        );

        return anyInternetInterface || null;
    }

    async detectLanInterface() {
        const interfaces = await this.getAllInterfaces();
        const wanInterface = await this.detectWanInterface();

        const lanCandidates = interfaces.filter(iface =>
            iface.status === 'up' &&
            !iface.isVirtual &&
            !iface.name.startsWith('br') &&
            (!wanInterface || iface.name !== wanInterface.name) &&
            iface.name !== 'lo'
        );

        if (lanCandidates.length > 0) {
            return lanCandidates[0];
        }

        return null;
    }

    async getRecommendedConfiguration() {
        const wanInterface = await this.detectWanInterface();
        const lanInterface = await this.detectLanInterface();

        return {
            wan: wanInterface,
            lan: lanInterface,
            availableInterfaces: await this.getAllInterfaces(),
            recommendations: {
                wanRecommended: wanInterface ? wanInterface.name : null,
                lanRecommended: lanInterface ? lanInterface.name : null,
                hasInternet: !!wanInterface,
                hasLanInterface: !!lanInterface
            }
        };
    }

    validateConfiguration(wanInterface, lanInterface) {
        const errors = [];

        if (!wanInterface) {
            errors.push('No WAN interface detected with internet connectivity');
        } else if (wanInterface.status !== 'up') {
            errors.push(`WAN interface ${wanInterface.name} is not up`);
        }

        if (!lanInterface) {
            errors.push('No LAN interface detected');
        } else if (lanInterface.status !== 'up') {
            errors.push(`LAN interface ${lanInterface.name} is not up`);
        }

        if (wanInterface && lanInterface && wanInterface.name === lanInterface.name) {
            errors.push('WAN and LAN interfaces cannot be the same');
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    }

    clearCache() {
        this.cachedInterfaces = null;
        this.lastCacheTime = 0;
    }

    startMonitoring(callback) {
        setInterval(() => {
            this.clearCache();
            if (callback) {
                this.getAllInterfaces().then(interfaces => {
                    callback(interfaces);
                });
            }
        }, 10000);
    }
}

module.exports = new InterfaceDetector();