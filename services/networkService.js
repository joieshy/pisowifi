const { exec } = require('child_process');
const fs = require('fs');
const util = require('util');
const execPromise = util.promisify(exec);

async function applyNetworkConfig(config) {
    const { wanIface, lanIface, lanIP, dns } = config;

    // Ang configuration na isusulat sa Ubuntu
    const netplanYaml = `
network:
  version: 2
  renderer: networkd
  ethernets:
    ${wanIface}:
      dhcp4: true
    ${lanIface}:
      addresses:
        - ${lanIP}
      nameservers:
        addresses: [${dns}]
`.trim();

    try {
        const tempPath = '/tmp/01-netcfg.yaml';
        const finalPath = '/etc/netplan/01-netcfg.yaml';
        
        fs.writeFileSync(tempPath, netplanYaml);

        await execPromise(`sudo mv ${tempPath} ${finalPath}`);
        await execPromise(`sudo chmod 600 ${finalPath}`);
        await execPromise(`sudo netplan apply`);

        return { success: true };
    } catch (error) {
        throw error;
    }
}

module.exports = { applyNetworkConfig }; // Importante ito para magamit sa server.js