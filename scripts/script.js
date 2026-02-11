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
