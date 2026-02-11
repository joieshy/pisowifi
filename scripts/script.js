const applyBtn = document.querySelector('button'); // Siguraduhin na ito ang tamang button selector

applyBtn.addEventListener('click', async () => {
    const payload = {
        wanIface: document.querySelector('[name="wan_name"]').value,
        lanIface: document.querySelector('[name="lan_name"]').value,
        lanIP: document.querySelector('input[placeholder="10.0.0.1/24"]').value,
        dns: document.querySelector('input[placeholder="8.8.8.8,8.8.4.4"]').value.split(',')
    };

    const res = await fetch('/api/save-network', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    const result = await res.json();
    alert(result.success ? "Success!" : "Failed: " + result.error);
});