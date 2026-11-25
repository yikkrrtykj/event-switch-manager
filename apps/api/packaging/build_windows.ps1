param(
    [string]$Python = "python",
    [string]$WebDist = "",
    [string]$OutputRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$apiRoot = Join-Path $repoRoot "apps\api"
$srcRoot = Join-Path $apiRoot "src"
$webDist = if ($WebDist) { (Resolve-Path $WebDist).Path } else { Join-Path $repoRoot "apps\web\dist" }
$outputRoot = if ($OutputRoot) { (Resolve-Path $OutputRoot).Path } else { Join-Path $apiRoot "dist" }
$buildRoot = Join-Path $apiRoot "build\packaging"
$stageRoot = Join-Path $buildRoot "stage"
$stageWeb = Join-Path $stageRoot "web"
$stageMigrations = Join-Path $stageRoot "migrations"
$packageName = "EventSwitchManager"
$packageDir = Join-Path $outputRoot $packageName
$exePath = Join-Path $packageDir "$packageName.exe"
$zipPath = Join-Path $outputRoot "$packageName-windows-x64.zip"
$recordPath = Join-Path $outputRoot "$packageName-build-record.json"

if (-not (Test-Path (Join-Path $webDist "index.html"))) {
    throw "Built web assets are missing index.html at $webDist. Run npm --prefix apps/web run build first."
}
if (-not (Test-Path (Join-Path $srcRoot "event_switch_manager\migrations\env.py"))) {
    throw "Alembic migrations are missing from the source package."
}
if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    throw "Python executable not found: $Python"
}
$pythonExe = (Get-Command $Python).Source
$previousEap = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
$version = (& $pythonExe -c "from importlib.metadata import version; print(version('event-switch-manager'))" 2>$null | Out-String).Trim()
$ErrorActionPreference = $previousEap
if (-not $version) { $version = "0.1.0" }
$gitSha = (& git -C $repoRoot rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $gitSha) { $gitSha = "unknown" }
$builtAt = (Get-Date).ToUniversalTime().ToString("o")
$pythonVersion = (& $pythonExe --version 2>&1 | Out-String).Trim()

foreach ($path in @($buildRoot, $stageRoot, $stageWeb, $stageMigrations)) {
    if (Test-Path $path) { Remove-Item -LiteralPath $path -Recurse -Force }
}
if (Test-Path $packageDir) { Remove-Item -LiteralPath $packageDir -Recurse -Force }
if (Test-Path $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
New-Item -ItemType Directory -Force -Path $stageWeb, $stageMigrations, $outputRoot | Out-Null

Copy-Item -LiteralPath (Join-Path $webDist "index.html") -Destination $stageWeb -Force
Copy-Item -LiteralPath (Join-Path $webDist "assets") -Destination $stageWeb -Recurse -Force
Copy-Item -Path (Join-Path $srcRoot "event_switch_manager\migrations\*") -Destination $stageMigrations -Recurse -Force
Get-ChildItem -LiteralPath $stageMigrations -Recurse -Directory -Force |
    Where-Object { $_.Name -eq "__pycache__" } |
    Remove-Item -Recurse -Force

$pyInstallerArgs = @(
    "-m", "PyInstaller",
    "--noconfirm", "--clean", "--onedir", "--console",
    "--name", $packageName,
    "--distpath", $outputRoot,
    "--workpath", (Join-Path $buildRoot "work"),
    "--specpath", (Join-Path $buildRoot "spec"),
    "--paths", $srcRoot,
    "--add-data", "$stageWeb;web",
    "--add-data", "$stageMigrations;event_switch_manager/migrations",
    "--collect-submodules", "uvicorn",
    "--collect-submodules", "alembic",
    "--collect-submodules", "sqlalchemy.dialects.sqlite",
    "--hidden-import", "uvicorn.logging",
    "--hidden-import", "uvicorn.loops.auto",
    "--hidden-import", "uvicorn.protocols.http.auto",
    "--hidden-import", "uvicorn.protocols.websockets.auto",
    "--hidden-import", "uvicorn.lifespan.on",
    (Join-Path $PSScriptRoot "launcher.py")
)
& $pythonExe @pyInstallerArgs
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }
if (-not (Test-Path $exePath)) { throw "Packaged executable was not created: $exePath" }
if (-not (Test-Path (Join-Path $packageDir "_internal\web\index.html"))) {
    throw "Packaged web assets were not placed under _internal/web."
}
if (-not (Test-Path (Join-Path $packageDir "_internal\event_switch_manager\migrations\env.py"))) {
    throw "Packaged Alembic migrations were not placed under _internal/event_switch_manager/migrations."
}

$forbidden = Get-ChildItem -LiteralPath $packageDir -Recurse -File -Force |
    Where-Object { $_.Extension -in @(".sqlite3", ".db", ".sqlite", ".env", ".pem", ".key") }
if ($forbidden) {
    throw "Forbidden data/secret file(s) found in package: $($forbidden.FullName -join ', ')"
}

Compress-Archive -LiteralPath $packageDir -DestinationPath $zipPath -CompressionLevel Optimal -Force
$exeHash = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$packageFiles = Get-ChildItem -LiteralPath $packageDir -Recurse -File -Force |
    ForEach-Object {
        [ordered]@{
            path = $_.FullName.Substring($packageDir.Length + 1).Replace("\", "/")
            bytes = $_.Length
        }
    }
$pipFreeze = @(& $pythonExe -m pip freeze 2>$null)
$record = [ordered]@{
    schema_version = 1
    package = "EventSwitchManager"
    platform = "windows-x64"
    version = "$version".Trim()
    git_sha = "$gitSha".Trim()
    built_at = $builtAt
    python = $pythonVersion
    package_dir = $packageDir
    executable = "EventSwitchManager/EventSwitchManager.exe"
    executable_sha256 = $exeHash
    zip = "EventSwitchManager-windows-x64.zip"
    zip_sha256 = $zipHash
    web_dist = $webDist
    static_assets_index_sha256 = (Get-FileHash -LiteralPath (Join-Path $webDist "index.html") -Algorithm SHA256).Hash.ToLowerInvariant()
    web_assets = @(Get-ChildItem -LiteralPath (Join-Path $webDist "assets") -File | Select-Object -ExpandProperty Name)
    migrations = @(
        "event_switch_manager/migrations/env.py",
        "event_switch_manager/migrations/script.py.mako",
        "event_switch_manager/migrations/versions/0001_event_inventory.py",
        "event_switch_manager/migrations/versions/0002_event_plans.py"
    )
    package_file_count = @($packageFiles).Count
    package_files = $packageFiles
    python_packages = $pipFreeze
    safety = [ordered]@{
        loopback_only = $true
        database_outside_package = $true
        no_credentials_or_test_database = $true
        device_connection = "none"
        configuration_generation = "not-implemented"
        deployment = "not-allowed"
    }
}
$record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $recordPath -Encoding utf8
Write-Output "PACKAGE=$packageDir"
Write-Output "EXE=$exePath"
Write-Output "ZIP=$zipPath"
Write-Output "RECORD=$recordPath"
Write-Output "EXE_SHA256=$exeHash"
Write-Output "ZIP_SHA256=$zipHash"
