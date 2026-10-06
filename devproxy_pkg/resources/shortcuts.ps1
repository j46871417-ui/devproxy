# User-owned shortcuts only. Data arrives as JSON on stdin, never shell code.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$shell = New-Object -ComObject WScript.Shell
$roots = @([Environment]::GetFolderPath('Desktop'), (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'), (Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'))
function Properties($path) {
    $link = $shell.CreateShortcut($path)
    return @{path=$path; target=$link.TargetPath; arguments=$link.Arguments; icon=$link.IconLocation; directory=$link.WorkingDirectory}
}
function Allowed($path) {
    $absolute = [IO.Path]::GetFullPath($path)
    foreach ($root in $roots) {
        if ($absolute.StartsWith([IO.Path]::GetFullPath($root) + '\', [StringComparison]::OrdinalIgnoreCase) -and $absolute.EndsWith('.lnk', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}
try {
    if ($payload.action -eq 'inspect') {
        $result = @()
        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Recurse | Select-Object -First 2000)) {
                $props = Properties $file.FullName
                if ($props.target -eq $payload.executable) { $result += $props }
            }
        }
        @{ok=$true; links=@($result)} | ConvertTo-Json -Depth 6 -Compress
    } elseif ($payload.action -eq 'write') {
        foreach ($edit in $payload.edits) {
            if (-not (Allowed $edit.path)) { throw 'Shortcut outside user locations' }
            $exists = Test-Path -LiteralPath $edit.path
            if ($null -eq $edit.expected) {
                if ($exists) { throw 'Refusing to replace an existing shortcut' }
            } else {
                if (-not $exists) { throw 'Shortcut missing' }
                $current = Properties $edit.path
                if ($current.target -ne $edit.expected.target -or $current.arguments -cne $edit.expected.arguments -or $current.icon -cne $edit.expected.icon -or $current.directory -cne $edit.expected.directory) { throw 'Shortcut changed by another application' }
            }
            if ($null -eq $edit.value) {
                Remove-Item -LiteralPath $edit.path
            } else {
                $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($edit.path))
                if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }
                $link = $shell.CreateShortcut($edit.path)
                $link.TargetPath = $edit.value.target
                $link.Arguments = $edit.value.arguments
                $link.IconLocation = $edit.value.icon
                $link.WorkingDirectory = $edit.value.directory
                $link.Save()
            }
        }
        @{ok=$true} | ConvertTo-Json -Compress
    } else { throw 'Unknown shortcut action' }
} catch {
    @{ok=$false; error='Не удалось изменить ярлык: он отсутствует, недоступен или изменён другой программой.'} | ConvertTo-Json -Compress
    exit 1
}
