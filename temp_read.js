const fs = require('fs');
for (const f of ['public/admin.html', 'services/networkService.js', 'server.js']) {
  console.log('\n### ' + f + ' ###\n');
  console.log(fs.readFileSync(f, 'utf8'));
}
