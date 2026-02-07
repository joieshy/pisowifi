# Phase 2: Rates Rendering + CSS Patch
$ErrorActionPreference = 'Stop'

$p = 'public/index.html'
$c = Get-Content -Path $p -Raw

Write-Host 'Applying Phase 2 (Rates Rendering + CSS)...'

# Find and replace the rates rendering block using regex
$oldPattern = [regex]::Escape('const ratesList = document.getElementById(''ratesList'');') + '[\s\S]*?' + [regex]::Escape('config.rates.forEach(rate => {') + '[\s\S]*?' + [regex]::Escape('ratesList.appendChild(rateItem);') + '\s*\}\);'

$newRatesRendering = @'
const ratesList = document.getElementById('ratesList');
                ratesList.innerHTML = '';

                if (!config.rates || config.rates.length === 0) {
                    ratesList.innerHTML = '<div class="rates-loading">No rates available</div>';
                    return;
                }

                const toMinutes = (duration, unit) => {
                    let mins = parseInt(duration, 10) || 0;
                    const u = (unit || '').toLowerCase();
                    if (u === 'hour' || u === 'hours') mins *= 60;
                    else if (u === 'day' || u === 'days') mins *= 1440;
                    return mins;
                };

                const withComputed = config.rates.map(r => {
                    const mins = toMinutes(r.duration, r.unit);
                    const amount = parseFloat(r.amount) || 0;
                    const ratio = amount > 0 ? (mins / amount) : 0;
                    return { ...r, mins, ratio };
                });

                const best = withComputed.reduce((acc, cur) => (cur.ratio > acc.ratio ? cur : acc), withComputed[0]);

                withComputed.forEach(rate => {
                    const card = document.createElement('div');
                    card.className = 'rate-card';

                    const unitDisplay = rate.duration > 1 ? (rate.unit.endsWith('s') ? rate.unit : rate.unit + 's') : rate.unit;

                    const isBest = best && rate.amount === best.amount && rate.duration === best.duration && rate.unit === best.unit;
                    if (isBest) {
                        const badge = document.createElement('div');
                        badge.className = 'rate-badge';
                        badge.innerHTML = '<i class="fas fa-crown"></i> Best Value';
                        card.appendChild(badge);
                    }

                    card.innerHTML += '<div class="rate-amount"><span class="peso">₱</span><span class="value">' + rate.amount + '</span></div><div class="rate-time"><i class="fas fa-clock"></i><span>' + rate.duration + ' ' + unitDisplay + '</span></div><div class="rate-meta"><i class="fas fa-hand-pointer"></i><span>Tap to insert coins</span></div>';

                    card.addEventListener('click', () => selectRateAndOpen(rate));
                    ratesList.appendChild(card);
                });
'@

$c = $c -replace $oldPattern, $newRatesRendering

# Replace old .rates CSS with new CSS
$oldCSSPattern = '\.rates \{[^}]+\}[\s]*\.rates::-webkit-scrollbar \{[^}]+\}[\s]*\.rates::-webkit-scrollbar-track \{[^}]+\}[\s]*\.rates::-webkit-scrollbar-thumb \{[^}]+\}[\s]*\.rate-item \{[^}]+\}'

$newCSS = @'
/* ===== Improved Rates UI ===== */
        .rates{margin-top:1.25rem;text-align:left;border-top:1px solid rgba(0,0,0,0.06);padding-top:1rem}.rates-header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}.rates-title{font-size:1.05rem;font-weight:800;letter-spacing:-0.2px;color:#1f2937}.rates-subtitle{font-size:0.82rem;color:#6b7280;margin-top:2px}.rates-pill{display:flex;align-items:center;gap:8px;font-size:0.75rem;font-weight:800;color:#1a73e8;background:rgba(26,115,232,0.10);border:1px solid rgba(26,115,232,0.20);padding:8px 10px;border-radius:999px;white-space:nowrap}.rates-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}@media (min-width:420px){.rates-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}.rate-card{cursor:pointer;position:relative;background:linear-gradient(180deg,rgba(255,255,255,0.95),rgba(248,250,252,0.95));border:1px solid rgba(15,23,42,0.08);border-radius:16px;padding:12px;box-shadow:0 10px 20px rgba(0,0,0,0.06);transition:transform 0.18s ease,box-shadow 0.18s ease,border-color 0.18s ease;overflow:hidden}.rate-card::before{content:"";position:absolute;inset:-2px;background:radial-gradient(circle at 20% 20%,rgba(26,115,232,0.22),transparent 55%);opacity:0;transition:opacity 0.2s ease;pointer-events:none}.rate-card:hover{transform:translateY(-2px);box-shadow:0 14px 28px rgba(0,0,0,0.10);border-color:rgba(26,115,232,0.25)}.rate-card:hover::before{opacity:1}.rate-card:active{transform:translateY(0px) scale(0.99)}.rate-amount{display:flex;align-items:baseline;gap:6px;font-weight:900;color:#111827}.rate-amount .peso{font-size:0.9rem;opacity:0.75}.rate-amount .value{font-size:1.6rem;letter-spacing:-0.5px}.rate-time{margin-top:6px;font-size:0.92rem;font-weight:800;color:#1a73e8;display:flex;align-items:center;gap:8px}.rate-meta{margin-top:6px;font-size:0.75rem;color:#6b7280;display:flex;align-items:center;gap:8px}.rate-badge{position:absolute;top:10px;right:10px;font-size:0.70rem;font-weight:900;color:#065f46;background:rgba(16,185,129,0.18);border:1px solid rgba(16,185,129,0.28);padding:6px 8px;border-radius:999px}.rates-loading{grid-column:1/-1;text-align:center;color:#6b7280;padding:14px 10px;background:rgba(0,0,0,0.03);border:1px dashed rgba(0,0,0,0.15);border-radius:16px}
'@

$c = $c -replace $oldCSSPattern, $newCSS

Set-Content -Path $p -Value $c -Encoding UTF8
Write-Host ''
Write-Host 'Phase 2 Complete!'
Write-Host 'All patches applied successfully.'
