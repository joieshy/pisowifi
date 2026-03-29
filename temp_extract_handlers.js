const fs = require('fs');
const html = fs.readFileSync('public/admin.html', 'utf8');
const patterns = [
  'function showSection',
  'function applyLanSettings',
  'function fetchLanSettings',
  'document.getElementById(\'networkInterfacesForm\')',
  'document.getElementById("networkInterfacesForm")',
  'networkInterfacesForm'
];
for (const p of patterns) {
  const idx = html.indexOf(p);
  console.log('\n### PATTERN:', p, 'INDEX:', idx, '###\n');
  if (idx !== -1) console.log(html.slice(Math.max(0, idx - 2500), Math.min(html.length, idx + 8000)));
}
