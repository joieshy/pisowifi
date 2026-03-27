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
        this.cacheTimeout = 5000; // 5 seconds cache
        this.lastCacheTime = 0;
    }

    /**
     * Get all available network interfaces with detailed information
     */
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
                // Windows implementation
                const output = execSync('powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq \'Up\'} | Select-Object -ExpandProperty Name"', { encoding: 'utf8' });
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
                // Fallback for other platforms
                return [];
            }
        } catch (error) {
            console.error('Error getting interfaces:', error.message);
            return [];
        }
    }

    /**
     * Get detailed information about a specific interface (Linux)
     */
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

            // Check if interface is up
            try {
                const operstate = execSync(`cat /sys/class/net/${interfaceName}/operstate`, { encoding: 'utf8' }).trim();
                details.status = operstate === 'up' ? 'up' : 'down';
            } catch (e) {
                details.status = 'down';
            }

            // Get MAC address
            try {
                const mac = execSync(`cat /sys/class/net/${interfaceName}/address`, { encoding: 'utf8' }).trim();
                details.macAddress = mac.toUpperCase();
            } catch (e) {
                // MAC might not be available for some interfaces
            }

            // Get IP address
            try {
                const ipOutput = execSync(`ip -4 addr show ${interfaceName}`, { encoding: 'utf8' });
                const ipMatch = ipOutput.match(/inet\s+(\d+\.\d+\.\d+\.\d+)/);
                if (ipMatch) {
                    details.ipAddress = ipMatch[1];
                }
            } catch (e) {
                // No IP assigned
            }

            // Check if wireless
            try {
                execSync(`test -d /sys/class/net/${interfaceName}/wireless`, { stdio: 'ignore' });
                details.isWireless = true;
            } catch (e) {
                details.isWireless = false;
            }

            // Check if virtual
            try {
                const type = execSync(`cat /sys/class/net/${interfaceName}/type`, { encoding: 'utf8' }).trim();
                // Type 772 is usually virtual/bridge interfaces
                details.isVirtual = type === '772';
            } catch (e) {
                details.isVirtual = false;
            }

            // Test internet connectivity if interface is up and has IP
            if (details.status === 'up' && details.ipAddress) {
                details.hasInternet = await this.testInternetConnectivity(interfaceName);
            }

            return details;
        } catch (error) {
            console.error(`Error getting details for ${interfaceName}:`, error.message);
            return null;
        }
    }

    /**
     * Get interface details for Windows
     */
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

            // Get interface status and details using PowerShell
            const psCommand = `
                $adapter = Get-NetAdapter -Name "${interfaceName}" -ErrorAction SilentlyContinue
                if ($adapter) {
                    $status = $adapter.Status
                    $mac = $adapter.MacAddress
                    $ipv4 = (Get-NetIPAddress -InterfaceAlias "${interfaceName}" -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
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

            // Test internet connectivity
            if (details.status === 'up' && details.ipAddress) {
                details.hasInternet = await this.testInternetConnectivity(interfaceName);
            }

            return details;
        } catch (error) {
            console.error(`Error getting Windows interface details for ${interfaceName}:`, error.message);
            return null;
        }
    }

    /**
     * Test internet connectivity for an interface
     */
    async testInternetConnectivity(interfaceName) {
        try {
            // Test connectivity using ping with specific interface
            if (os.platform() === 'linux') {
                // Try sudo ping first, then fallback to regular ping
                try {
                    const result = await execPromise(
                        `sudo timeout 5 ping -I ${interfaceName} -c 2 8.8.8.8`, 
                        { timeout: 6000 }
                    );
                    return result.stdout.includes('2 packets transmitted, 2 received') || 
                           result.stdout.includes('2 packets transmitted, 1 received');
                } catch (sudoError) {
                    // If sudo ping fails, try regular ping (may fail due to permissions)
                    try {
                        const result = await execPromise(
                            `timeout 5 ping -I ${interfaceName} -c 2 8.8.8.8`, 
                            { timeout: 6000 }
                        );
                        return result.stdout.includes('2 packets transmitted, 2 received') || 
                               result.stdout.includes('2 packets transmitted, 1 received');
                    } catch (regularError) {
                        // If ping fails due to permissions, try alternative connectivity check
                        return await this.checkConnectivityAlternative(interfaceName);
                    }
                }
            } else if (os.platform() === 'win32') {
                // Windows ping with specific interface (more complex)
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

    /**
     * Alternative connectivity check when ping fails due to permissions
     * Uses curl/wget to test internet connectivity
     */
    async checkConnectivityAlternative(interfaceName) {
        try {
            // Try curl first
            try {
                const result = await execPromise(
                    `curl --interface ${interfaceName} --connect-timeout 5 --head 8.8.8.8`, 
                    { timeout: 6000 }
                );
                return result.stdout.includes('HTTP/');
            } catch (curlError) {
                // Try wget as fallback
                try {
                    const result = await execPromise(
                        `wget --timeout=5 --spider --bind-address=${interfaceName} 8.8.8.8`, 
                        { timeout: 6000 }
                    );
                    return result.stdout.includes('HTTP request sent');
                } catch (wgetError) {
                    // Try nslookup for DNS resolution test
                    const result = await execPromise(
                        `nslookup 8.8.8.8 ${interfaceName}`, 
                        { timeout: 6000 }
                    );
                    return result.stdout.includes('Name:') || result.stdout.includes('Address:');
                }
            }
        } catch (e) {
            return false;
        }
    }

    /**
     * Automatically detect WAN interface (interface with internet connectivity)
     */
    async detectWanInterface() {
        const interfaces = await this.getAllInterfaces();
        
        // Filter for interfaces that are up, have IP, and have internet
        const wanCandidates = interfaces.filter(iface => 
            iface.status === 'up' && 
            iface.ipAddress && 
            iface.hasInternet &&
            !iface.isVirtual &&
            !iface.isWireless // Typically WAN is wired, but this can be configurable
        );

        if (wanCandidates.length > 0) {
            // Return the first interface with internet (usually the best candidate)
            return wanCandidates[0];
        }

        // If no wired interface has internet, try wireless interfaces
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

        // If still no candidates, return the first interface with internet regardless of type
        const anyInternetInterface = interfaces.find(iface => 
            iface.status === 'up' && 
            iface.ipAddress && 
            iface.hasInternet
        );

        return anyInternetInterface || null;
    }

    /**
     * Automatically detect LAN interface (interface for client connections)
     */
    async detectLanInterface() {
        const interfaces = await this.getAllInterfaces();
        const wanInterface = await this.detectWanInterface();
        
        // Filter for interfaces that are not WAN, not virtual, and are up
        const lanCandidates = interfaces.filter(iface => 
            iface.status === 'up' && 
            !iface.isVirtual &&
            (!wanInterface || iface.name !== wanInterface.name) &&
            iface.name !== 'lo' // Exclude loopback
        );

        if (lanCandidates.length > 0) {
            // Return the first available LAN interface
            return lanCandidates[0];
        }

        return null;
    }

    /**
     * Get recommended interface configuration
     */
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

    /**
     * Validate interface configuration
     */
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

    /**
     * Clear interface cache
     */
    clearCache() {
        this.cachedInterfaces = null;
        this.lastCacheTime = 0;
    }

    /**
     * Monitor interface changes (for future implementation)
     */
    startMonitoring(callback) {
        // This could be implemented to monitor /sys/class/net for changes
        // For now, just clear cache periodically
        setInterval(() => {
            this.clearCache();
            if (callback) {
                this.getAllInterfaces().then(interfaces => {
                    callback(interfaces);
                });
            }
        }, 10000); // Check every 10 seconds
    }
}

// Export singleton instance
module.exports = new InterfaceDetector();