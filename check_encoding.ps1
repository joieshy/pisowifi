$bytes = [System.IO.File]::ReadAllBytes('public/index.html')
if ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    Write-Host 'BOM detected (UTF-8 with BOM) - This may cause encoding issues'
    Write-Host 'Removing BOM...'
    $content = Get-Content 'public/index.html' -Raw
    [System.IO.File]::WriteAllText('public/index.html', $content, (New-Object System.Text.UTF8Encoding $false))
    Write-Host 'BOM removed successfully'
} else {
    Write-Host 'No BOM detected - file is clean UTF-8'
}
