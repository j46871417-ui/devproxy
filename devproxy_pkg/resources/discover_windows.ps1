# Read-only discovery. No user-supplied shell code or arguments.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$entries = [System.Collections.Generic.List[object]]::new()
$shell = New-Object -ComObject WScript.Shell
$roots = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs")
foreach ($root in $roots) {
    Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 2000 | ForEach-Object {
            $shortcut = $shell.CreateShortcut($_.FullName)
            if ($shortcut.TargetPath -like '*.exe') {
                $entries.Add(@{ name = $_.BaseName; path = $shortcut.TargetPath; location = ''; source = 'shortcut' })
            }
        }
}
Get-AppxPackage | Where-Object { $_.Name -match 'Codex|OpenCode|VisualStudioCode|Cursor|Windsurf|Antigravity|Zed' } |
    Select-Object -First 100 | ForEach-Object {
        $entries.Add(@{ name = $_.Name; path = ''; location = $_.InstallLocation; source = 'package' })
    }
ConvertTo-Json -InputObject @($entries) -Compress -Depth 3
