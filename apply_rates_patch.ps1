# Simple Patch Script for Rates UI - Fixed version
$ErrorActionPreference = 'Stop'

$p = 'public/index.html'
$backup = "$p" + '.bak'
Copy-Item -Path $p -Destination $backup -Force
Write-Host "Backup created at $backup"

$c = Get-Content -Path $p -Raw

# Replace 1: Rates HTML block
$c = $c.Replace(
    '<div class="rates">' + "`r`n" + '            <strong>Rates:</strong>' + "`r`n" + '            <div id="ratesList">' + "`r`n" + '                <div style="text-align: center; color: #888;">Loading rates...</div>' + "`r`n" + '            </div>' + "`r`n" + '        </div>',
    '<div class="rates">' + "`r`n" + '            <div class="rates-header">' + "`r`n" + '                <div>' + "`r`n" + '                    <div class="rates-title">Rates</div>' + "`r`n" + '                    <div class="rates-subtitle">Tap a promo to start</div>' + "`r`n" + '                </div>' + "`r`n" + '                <div class="rates-pill">' + "`r`n" + '                    <i class="fas fa-hand-pointer"></i> Clickable' + "`r`n" + '                </div>' + "`r`n" + '            </div>' + "`r`n" + "`r`n" + '            <div id="ratesList" class="rates-grid">' + "`r`n" + '                <div class="rates-loading">' + "`r`n" + '                    <i class="fas fa-spinner fa-spin"></i> Loading rates...' + "`r`n" + '                </div>' + "`r`n" + '            </div>' + "`r`n" + '        </div>'
)

# Replace 2: Add promoHint div
$c = $c.Replace(
    '<p class="modal-text">Please drop your coins now.</p>',
    '<p class="modal-text">Please drop your coins now.</p>' + "`r`n" + '            <div id="promoHint" style="display:none; margin: 0.75rem 0 0; padding: 10px 12px; border-radius: 12px; background: rgba(26,115,232,0.08); border: 1px solid rgba(26,115,232,0.18); color:#1a73e8; font-weight: 700; font-size: 0.9rem;"></div>'
)

# Replace 3: Add selectedRate after audioCtx
$c = $c.Replace(
    '        let audioCtx;',
    '        let audioCtx;' + "`r`n" + '        let selectedRate = null;'
)

#Replace 4: Add selectRateAndOpen function
$functionCode = @'

        function selectRateAndOpen(rate) {
            selectedRate = rate;
            showInsertCoinModal();
            const promoHint = document.getElementById('promoHint');
            if (promoHint) {
                const unitDisplay = rate.duration > 1 ? (rate.unit.endsWith('s') ? rate.unit : rate.unit + 's') : rate.unit;
                promoHint.style.display = 'block';
                promoHint.innerHTML = '<i class="fas fa-tag"></i> Target Promo: <b>₱' + rate.amount + '</b> = <b>' + rate.duration + ' ' + unitDisplay + '</b>';
            }
        }
'@

$c = $c.Replace(
    '        let selectedRate = null;',
    '        let selectedRate = null;' + $functionCode
)

# Replace 5: Update showInsertCoinModal
$c = $c.Replace(
    "            modal.style.display = 'flex';",
    "            modal.style.display = 'flex';`r`n            const promoHint = document.getElementById('promoHint');`r`n            if (promoHint && !selectedRate) { promoHint.style.display = 'none'; promoHint.innerHTML = ''; }"
)

# Replace 6: Update hideInsertCoinModal
$c = $c.Replace(
    '            audio.currentTime = 0;' + "`r`n" + '        }',
    '            audio.currentTime = 0;' + "`r`n" + '            selectedRate = null;' + "`r`n" + "            const promoHint = document.getElementById('promoHint');`r`n            if (promoHint) { promoHint.style.display = 'none'; promoHint.innerHTML = ''; }`r`n        }"
)

Set-Content -Path $p -Value $c -Encoding UTF8

Write-Host ''
Write-Host 'Success - Patched Phase 1 (HTML/JS updates) completed'
Write-Host ''
Write-Host 'NOTE: Phase 2 (rates rendering cards + CSS) requires manual editing.'
Write-Host 'Please check the file. Backup available at:' $backup
