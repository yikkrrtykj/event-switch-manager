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
$zipPath = Join-Path $outputRoot "$packageName-windows-x64.zip"
$recordPath = Join-Path $outputRoot "$packageName-build-record.json"
$packageRecordPath = Join-Path $packageDir "$packageName-build-record.json"
$launcher = Join-Path $PSScriptRoot "launcher.py"
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

if (-not (Test-Path $launcher)) { throw "ConsoleLab launcher is missing." }
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

$pyInstallerArgs = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onedir",
    "--console",
    "--name", $packageName,
    "--distpath", $outputRoot,
    "--workpath", (Join-Path $buildRoot "work"),
    "--specpath", $buildRoot,
    "--paths", $srcRoot,
    "--collect-submodules", "event_switch_manager.lab_runner",
    "--collect-submodules", "event_switch_manager.console",
    "--collect-submodules", "serial",
    "--collect-submodules", "serial.tools",
    "--hidden-import", "serial.tools.list_ports",
    "--hidden-import", "serial.tools.list_ports_windows",
    "--hidden-import", "serial.tools.list_ports_linux",
    $launcher
)
& $pythonExe @pyInstallerArgs
if ($LASTEXITCODE -ne 0) { throw "ConsoleLab PyInstaller build failed." }
if (-not (Test-Path $exePath)) { throw "ConsoleLab executable was not produced." }
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
$sums = "$exeHash  $packageName/EventSwitchManager-ConsoleLab.exe`n$zipHash  $packageName-windows-x64.zip`n"
[IO.File]::WriteAllText((Join-Path $outputRoot "SHA256SUMS.console-lab"), $sums, (New-Object System.Text.UTF8Encoding($false)))
Write-Output "PACKAGE=$packageDir"
Write-Output "EXE=$exePath"
Write-Output "ZIP=$zipPath"
Write-Output "RECORD=$recordPath"
Write-Output "EXE_SHA256=$exeHash"
Write-Output "ZIP_SHA256=$zipHash"
