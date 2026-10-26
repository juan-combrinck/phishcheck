# Creates a PhishCheck shortcut (with the logo) on the Desktop and in the Start Menu.
$root = $PSScriptRoot
$ws = New-Object -ComObject WScript.Shell
foreach ($dir in @([Environment]::GetFolderPath('Desktop'), (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'))) {
    $lnk = $ws.CreateShortcut((Join-Path $dir 'PhishCheck.lnk'))
    $lnk.TargetPath = Join-Path $env:WINDIR 'System32\wscript.exe'
    $lnk.Arguments = '"' + (Join-Path $root 'launch.vbs') + '"'
    $lnk.WorkingDirectory = $root
    $lnk.IconLocation = (Join-Path $root 'assets\icon.ico') + ',0'
    $lnk.Description = 'PhishCheck - static email threat analyzer'
    $lnk.Save()
    Write-Host "Created $($lnk.FullName)"
}
