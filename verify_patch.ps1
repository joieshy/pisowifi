$c = Get-Content 'public/index.html' -Raw
$checks = @()
if ($c -like '*selectRateAndOpen*') { $checks += 'selectRateAndOpen' }
if ($c -like '*rate-card*') { $checks += 'rate-card CSS' }
if ($c -like '*rates-grid*') { $checks += 'rates-grid' }
if ($c -like '*promoHint*') { $checks += 'promoHint' }
if ($c -like '*Best Value*') { $checks += 'Best Value badge' }
if ($c -like '*toMinutes*') { $checks += 'toMinutes function' }
Write-Host 'Verified components:'
$checks | ForEach-Object { Write-Host "  - $_" }
