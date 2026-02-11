document.addEventListener('DOMContentLoaded', () => {
    const applyNetworkConfigBtn = document.getElementById('applyNetworkConfig'); // Assuming an ID for the button
    const wanInterfaceNameInput = document.getElementById('wanInterfaceName');
    const wanConfigTypeDhcp = document.getElementById('wanConfigTypeDhcp');
    const wanConfigTypeStatic = document.getElementById('wanConfigTypeStatic');
    const wanIpAddressInput = document.getElementById('wanIpAddress');
    const wanGatewayInput = document.getElementById('wanGateway');
    const wanDnsServersInput = document.getElementById('wanDnsServers');
    const lanInterfaceNameInput = document.getElementById('lanInterfaceName');
    const lanIpAddressInput = document.getElementById('lanIpAddress');
    const lanDnsServersInput = document.getElementById('lanDnsServers');

    // Function to toggle visibility of static WAN fields
    function toggleWanStaticFields() {
        const isStatic = wanConfigTypeStatic.checked;
        wanIpAddressInput.disabled = !isStatic;
        wanGatewayInput.disabled = !isStatic;
        wanDnsServersInput.disabled = !isStatic;
    }

    // Initial call to set correct state
    toggleWanStaticFields();

    // Add event listeners for WAN config type radio buttons
    wanConfigTypeDhcp.addEventListener('change', toggleWanStaticFields);
    wanConfigTypeStatic.addEventListener('change', toggleWanStaticFields);

    if (applyNetworkConfigBtn) {
        applyNetworkConfigBtn.addEventListener('click', async () => {
            const wanConfigType = wanConfigTypeDhcp.checked ? 'dhcp' : 'static';
            const wanDnsServers = wanDnsServersInput.value.split(',').map(s => s.trim()).filter(s => s.length > 0);
            const lanDnsServers = lanDnsServersInput.value.split(',').map(s => s.trim()).filter(s => s.length > 0);

            const payload = {
                wan_interface_name: wanInterfaceNameInput.value,
                wan_config_type: wanConfigType,
                wan_ip_address: wanIpAddressInput.value,
                wan_gateway: wanGatewayInput.value,
                wan_dns_servers: wanDnsServers,
                lan_interface_name: lanInterfaceNameInput.value,
                lan_ip_address: lanIpAddressInput.value,
                lan_dns_servers: lanDnsServers
            };

            try {
                const res = await fetch('/api/save-network', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const result = await res.json();
                alert(result.success ? "Network configuration applied successfully!" : "Failed to apply network configuration: " + result.error);
            } catch (error) {
                console.error('Error applying network configuration:', error);
                alert('An error occurred while applying network configuration.');
            }
        });
    }

    // Fetch and populate current settings on load
    async function fetchNetworkSettings() {
        try {
            const res = await fetch('/api/network/interfaces');
            const settings = await res.json();

            wanInterfaceNameInput.value = settings.wan_interface_name || '';
            if (settings.wan_config_type === 'static') {
                wanConfigTypeStatic.checked = true;
            } else {
                wanConfigTypeDhcp.checked = true;
            }
            wanIpAddressInput.value = settings.wan_ip_address || '';
            wanGatewayInput.value = settings.wan_gateway || '';
            wanDnsServersInput.value = settings.wan_dns_servers ? settings.wan_dns_servers.join(', ') : '';
            lanInterfaceNameInput.value = settings.lan_interface_name || '';
            lanIpAddressInput.value = settings.lan_ip_address || '';
            lanDnsServersInput.value = settings.lan_dns_servers ? settings.lan_dns_servers.join(', ') : '';

            toggleWanStaticFields(); // Apply correct disabled state after loading settings
        } catch (error) {
            console.error('Error fetching network settings:', error);
            alert('Failed to load network settings.');
        }
    }

    fetchNetworkSettings();
});

// Serial Port Functions
async function fetchSerialPorts() {
    const comPortSelect = document.getElementById('comPortSelect');
    comPortSelect.innerHTML = '<option value="">-- Select a port --</option>'; // Reset options
    const serialPortStatus = document.getElementById('serialPortStatus');
    const serialPortMsg = document.getElementById('serialPortMsg');
    serialPortMsg.style.display = 'none';

    try {
        const response = await fetch('/api/serial-ports');
        const ports = await response.json();

        if (ports.length > 0) {
            ports.forEach(port => {
                const option = document.createElement('option');
                option.value = port.path;
                option.innerText = `${port.path} (${port.manufacturer})`;
                comPortSelect.appendChild(option);
            });
            comPortSelect.value = localStorage.getItem('selectedSerialPort') || ''; // Restore last selected
        } else {
            comPortSelect.innerHTML = '<option value="">-- No ports detected --</option>';
        }
    } catch (e) {
        console.error('Error fetching serial ports:', e);
        serialPortMsg.style.color = 'var(--danger-color)';
        serialPortMsg.innerText = 'Failed to fetch serial ports.';
        serialPortMsg.style.display = 'block';
    }
}

async function connectSerialPort() {
    const comPortSelect = document.getElementById('comPortSelect');
    const portPath = comPortSelect.value;
    const serialPortStatus = document.getElementById('serialPortStatus');
    const serialPortMsg = document.getElementById('serialPortMsg');
    serialPortMsg.style.display = 'none';

    if (!portPath) {
        serialPortMsg.style.color = 'var(--danger-color)';
        serialPortMsg.innerText = 'Please select a COM port.';
        serialPortMsg.style.display = 'block';
        return;
    }

    serialPortStatus.innerText = 'Connecting...';
    serialPortStatus.className = 'badge badge-warning';

    try {
        const response = await fetch('/api/serial-port/connect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ portPath })
        });
        const result = await response.json();

        if (response.ok) {
            serialPortStatus.innerText = 'Connected';
            serialPortStatus.className = 'badge badge-online';
            serialPortMsg.style.color = 'var(--success-color)';
            serialPortMsg.innerText = result.message;
            localStorage.setItem('selectedSerialPort', portPath); // Save selected port
        } else {
            serialPortStatus.innerText = 'Disconnected';
            serialPortStatus.className = 'badge badge-offline';
            serialPortMsg.style.color = 'var(--danger-color)';
            serialPortMsg.innerText = result.error || 'Failed to connect.';
        }
        serialPortMsg.style.display = 'block';
        setTimeout(() => serialPortMsg.style.display = 'none', 5000);
    } catch (e) {
        console.error('Error connecting to serial port:', e);
        serialPortStatus.innerText = 'Disconnected';
        serialPortStatus.className = 'badge badge-offline';
        serialPortMsg.style.color = 'var(--danger-color)';
        serialPortMsg.innerText = 'Network error or server issue.';
        serialPortMsg.style.display = 'block';
        setTimeout(() => serialPortMsg.style.display = 'none', 5000);
    }
}

// Extend fetchSystemInfo to also fetch serial ports
const originalFetchSystemInfo = fetchSystemInfo;
fetchSystemInfo = async () => {
    await originalFetchSystemInfo();
    fetchSerialPorts(); // Fetch serial ports when system info is loaded
};

// Function to fetch available network interfaces and populate dropdowns
async function fetchAvailableNetworkInterfaces() {
    try {
        const response = await fetch('/api/network/available-interfaces');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const interfaces = await response.json();
        console.log('Fetched network interfaces:', interfaces);

        const wanSelect = document.getElementById('wan_interface_name');
        const lanSelect = document.getElementById('lan_interface_name');

        // Clear existing options and add default "select" options
        wanSelect.innerHTML = '<option value="">-- Select WAN Interface --</option>';
        lanSelect.innerHTML = '<option value="">-- Select LAN Interface --</option>';

        if (interfaces.length === 0) {
            wanSelect.innerHTML = '<option value="">No interfaces detected</option>';
            lanSelect.innerHTML = '<option value="">No interfaces detected</option>';
            return;
        }

        // Populate dropdowns
        interfaces.forEach(iface => {
            const wanOption = document.createElement('option');
            wanOption.value = iface;
            wanOption.innerText = iface;
            wanSelect.appendChild(wanOption);

            const lanOption = document.createElement('option');
            lanOption.value = iface;
            lanOption.innerText = iface;
            lanSelect.appendChild(lanOption);
        });

        // Fetch current network settings to pre-select values
        const settingsResponse = await fetch('/api/network/interfaces');
        const settings = await settingsResponse.json();

        if (settings.wan_interface_name) {
            wanSelect.value = settings.wan_interface_name;
        }
        if (settings.lan_interface_name) {
            lanSelect.value = settings.lan_interface_name;
        }

    } catch (e) {
        console.error('Error fetching available network interfaces:', e);
        const wanSelect = document.getElementById('wan_interface_name');
        const lanSelect = document.getElementById('lan_interface_name');
        wanSelect.innerHTML = '<option value="">Error loading interfaces</option>';
        lanSelect.innerHTML = '<option value="">Error loading interfaces</option>';
        alert('Error loading network interfaces: ' + e.message); // Added alert for user feedback
    }
}

// Modify fetchNetwork to also call fetchAvailableNetworkInterfaces
const originalFetchNetwork = fetchNetwork;
fetchNetwork = async () => {
    await originalFetchNetwork();
    await fetchAvailableNetworkInterfaces();
};
