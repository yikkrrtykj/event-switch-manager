param(
    [string]$Python = "python",
    [string]$OutputRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..")).Path
$apiRoot = Join-Path $repoRoot "apps\api"
$srcRoot = Join-Path $apiRoot "src"
$outputRoot = if ($OutputRoot) { (Resolve-Path $OutputRoot -ErrorAction SilentlyContinue).Path } else { Join-Path $apiRoot "dist-console-lab" }
if (-not $outputRoot) { $outputRoot = [IO.Path]::GetFullPath($OutputRoot) }
$buildRoot = Join-Path $apiRoot "build\console-lab"
$stageRoot = Join-Path $buildRoot "stage"
$stageInstructions = Join-Path $stageRoot "instructions"
$packageName = "EventSwitchManager-ConsoleLab"
$packageDir = Join-Path $outputRoot $packageName
$exePath = Join-Path $packageDir "$packageName.exe"
$cliExeName = "$packageName-CLI"
$cliExePath = Join-Path $packageDir "$cliExeName.exe"
$zipPath = Join-Path $outputRoot "$packageName-windows-x64.zip"
$recordPath = Join-Path $outputRoot "$packageName-build-record.json"
$packageRecordPath = Join-Path $packageDir "$packageName-build-record.json"
$guiLauncher = Join-Path $PSScriptRoot "gui_launcher.py"
$cliLauncher = Join-Path $PSScriptRoot "cli_launcher.py"
$specPath = Join-Path $buildRoot "console_lab.spec"
$instructions = Join-Path $PSScriptRoot "README.zh-CN.txt"
$acceptance = Join-Path $PSScriptRoot "H0-H4-ACCEPTANCE-TEMPLATE.txt"

if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    throw "Python executable not found: $Python"
}
$pythonExe = (Get-Command $Python).Source
$gitSha = (& git -C $repoRoot rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $gitSha) { $gitSha = "unknown" }
$builtAt = (Get-Date).ToUniversalTime().ToString("o")
$pythonVersion = (& $pythonExe --version 2>&1 | Out-String).Trim()
$version = (& $pythonExe -c "from importlib.metadata import version; print(version('event-switch-manager'))" 2>$null | Out-String).Trim()
if (-not $version) { $version = "0.1.0" }
$pyserialVersion = (& $pythonExe -c "import serial; print(serial.__version__)" 2>$null | Out-String).Trim()

if (-not (Test-Path $guiLauncher)) { throw "ConsoleLab GUI launcher is missing." }
if (-not (Test-Path $cliLauncher)) { throw "ConsoleLab CLI launcher is missing." }
if (-not (Test-Path $instructions)) { throw "ConsoleLab instructions are missing." }
if (-not (Test-Path $acceptance)) { throw "H0-H4 acceptance template is missing." }

foreach ($path in @($buildRoot, $stageRoot, $stageInstructions)) {
    if (Test-Path $path) { Remove-Item -LiteralPath $path -Recurse -Force }
}
if (Test-Path $packageDir) { Remove-Item -LiteralPath $packageDir -Recurse -Force }
if (Test-Path $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
New-Item -ItemType Directory -Force -Path $stageInstructions, $outputRoot | Out-Null
Copy-Item -LiteralPath $instructions -Destination (Join-Path $stageInstructions "README.zh-CN.txt") -Force
Copy-Item -LiteralPath $acceptance -Destination (Join-Path $stageInstructions "H0-H4-ACCEPTANCE-TEMPLATE.txt") -Force

$srcSpec = $srcRoot.Replace("\", "/")
$guiSpec = $guiLauncher.Replace("\", "/")
$cliSpec = $cliLauncher.Replace("\", "/")
$specContent = @"
# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

src = r"$srcSpec"
hidden = (
    collect_submodules("event_switch_manager.lab_runner")
    + collect_submodules("event_switch_manager.console")
    + collect_submodules("serial")
    + collect_submodules("serial.tools")
    + [
        "serial.tools.list_ports",
        "serial.tools.list_ports_windows",
        "serial.tools.list_ports_linux",
        "tkinter", "tkinter.ttk", "tkinter.messagebox", "tkinter.scrolledtext",
    ]
)
a_gui = Analysis(
    [r"$guiSpec"], pathex=[src], binaries=[], datas=[],
    hiddenimports=hidden, hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=[], noarchive=False, optimize=0,
)
a_cli = Analysis(
    [r"$cliSpec"], pathex=[src], binaries=[], datas=[],
    hiddenimports=hidden, hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=[], noarchive=False, optimize=0,
)
pyz_gui = PYZ(a_gui.pure)
pyz_cli = PYZ(a_cli.pure)
exe_gui = EXE(
    pyz_gui, a_gui.scripts, [], exclude_binaries=True,
    name="$packageName", debug=False, bootloader_ignore_signals=False,
    strip=False, upx=False, console=False, disable_windowed_traceback=False,
    argv_emulation=False, target_arch=None, codesign_identity=None,
    entitlements_file=None,
)
exe_cli = EXE(
    pyz_cli, a_cli.scripts, [], exclude_binaries=True,
    name="$cliExeName", debug=False, bootloader_ignore_signals=False,
    strip=False, upx=False, console=True, disable_windowed_traceback=False,
    argv_emulation=False, target_arch=None, codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe_gui, a_gui.binaries, a_gui.datas,
    exe_cli, a_cli.binaries, a_cli.datas,
    strip=False, upx=False, name="$packageName",
)
"@
New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null
[IO.File]::WriteAllText($specPath, $specContent, (New-Object System.Text.UTF8Encoding($false)))
$pyInstallerArgs = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--distpath", $outputRoot,
    "--workpath", (Join-Path $buildRoot "work"),
    $specPath
)
& $pythonExe @pyInstallerArgs
if ($LASTEXITCODE -ne 0) { throw "ConsoleLab PyInstaller build failed." }
if (-not (Test-Path $exePath)) { throw "ConsoleLab GUI executable was not produced." }
if (-not (Test-Path $cliExePath)) { throw "ConsoleLab CLI executable was not produced." }
$packageInstructions = Join-Path $packageDir "instructions"
New-Item -ItemType Directory -Force -Path $packageInstructions | Out-Null
Copy-Item -LiteralPath $instructions -Destination (Join-Path $packageInstructions "README.zh-CN.txt") -Force
Copy-Item -LiteralPath $acceptance -Destination (Join-Path $packageInstructions "H0-H4-ACCEPTANCE-TEMPLATE.txt") -Force
$manifestPath = Join-Path $packageDir "DEPENDENCIES-SHA256SUMS.txt"
$manifestLines = Get-ChildItem -LiteralPath $packageDir -Recurse -File |
    Where-Object { $_.FullName -ne $manifestPath } |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($packageDir.Length + 1).Replace("\", "/")
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relative"
    }
[IO.File]::WriteAllLines($manifestPath, $manifestLines, (New-Object System.Text.UTF8Encoding($false)))
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

$exeHash = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
$cliExeHash = (Get-FileHash -LiteralPath $cliExePath -Algorithm SHA256).Hash.ToLowerInvariant()
$record = [ordered]@{
    schema_version = 1
    package = $packageName
    version = $version
    git_sha = $gitSha
    built_at = $builtAt
    python = $pythonVersion
    pyserial = $pyserialVersion
    executable = "EventSwitchManager-ConsoleLab.exe"
    executable_sha256 = $exeHash
    gui_console_subsystem = 2
    cli_executable = "$cliExeName.exe"
    cli_executable_sha256 = $cliExeHash
    cli_console_subsystem = 3
    zip_sha256 = ""
    no_host_python = $true
    no_node = $true
    no_web_service = $true
    no_product_database = $true
    offline = $true
    instructions = "instructions/README.zh-CN.txt"
    acceptance_template = "instructions/H0-H4-ACCEPTANCE-TEMPLATE.txt"
    dependencies_manifest = "DEPENDENCIES-SHA256SUMS.txt"
    dependencies_manifest_sha256 = $manifestHash
    lab_source = "AUTHORIZED_LIVE_LAB"
    product_live_serial = "DISABLED"
    real_serial_completion = "NOT_VERIFIED"
    hardware_verified = $false
}
$recordJson = $record | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($packageRecordPath, $recordJson + "`n", (New-Object System.Text.UTF8Encoding($false)))
if (Test-Path $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
Compress-Archive -LiteralPath $packageDir -DestinationPath $zipPath -CompressionLevel Optimal
$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$record.zip_sha256 = $zipHash
$recordJson = $record | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($recordPath, $recordJson + "`n", (New-Object System.Text.UTF8Encoding($false)))
$sums = "$exeHash  $packageName/EventSwitchManager-ConsoleLab.exe`n$cliExeHash  $packageName/$cliExeName.exe`n$zipHash  $packageName-windows-x64.zip`n"
[IO.File]::WriteAllText((Join-Path $outputRoot "SHA256SUMS.console-lab"), $sums, (New-Object System.Text.UTF8Encoding($false)))
Write-Output "PACKAGE=$packageDir"
Write-Output "EXE=$exePath"
Write-Output "ZIP=$zipPath"
Write-Output "RECORD=$recordPath"
Write-Output "CLI_EXE=$cliExePath"
Write-Output "EXE_SHA256=$exeHash"
Write-Output "CLI_EXE_SHA256=$cliExeHash"
Write-Output "ZIP_SHA256=$zipHash"
