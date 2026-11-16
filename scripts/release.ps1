# Build a signed release and publish it to GitHub Releases.
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\release.ps1 -NotesFile docs\releases\0.2.0.md
#         (UTF-8 notes file) or -Notes "one line"; add -NoBuild to publish the existing build, -Draft for a draft.
# The updater signing key lives outside the repo in %USERPROFILE%\.tauri (password DPAPI-encrypted).
param(
  [string]$Notes,
  [string]$NotesFile,
  [switch]$NoBuild,
  [switch]$Draft,
  [string]$Repo = "refonuz-art/GhostMonit-r"
)
$ErrorActionPreference = "Stop"
if ($NotesFile) { $Notes = [IO.File]::ReadAllText((Resolve-Path $NotesFile), [Text.Encoding]::UTF8).Trim() }
if (-not $Notes) { throw "pass -Notes or -NotesFile" }
$root = Split-Path $PSScriptRoot -Parent
$conf = Get-Content "$root\src-tauri\tauri.conf.json" -Raw | ConvertFrom-Json
$ver = $conf.version
$tag = "v$ver"

$keyDir = Join-Path $env:USERPROFILE ".tauri"
$env:TAURI_SIGNING_PRIVATE_KEY = Get-Content "$keyDir\ghostmonitor-updater.key" -Raw
$sec = Get-Content "$keyDir\ghostmonitor-updater.pw" | ConvertTo-SecureString
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))

if (-not $NoBuild) {
  Push-Location $root
  try { pnpm app:build; if ($LASTEXITCODE) { throw "build failed" } } finally { Pop-Location }
}

$nsis = "$root\src-tauri\target\release\bundle\nsis"
$setup = Get-ChildItem $nsis -Filter "*_${ver}_x64-setup.exe" | Select-Object -First 1
if (-not $setup) { throw "installer for $ver not found in $nsis" }
$sig = Get-Content "$($setup.FullName).sig" -Raw

# GitHub turns spaces into dots in asset names; publish under a stable name instead.
$out = Join-Path $nsis "release"
New-Item -ItemType Directory -Force $out | Out-Null
$asset = "GhostMonitor_${ver}_x64-setup.exe"
Copy-Item $setup.FullName (Join-Path $out $asset) -Force

$manifest = [ordered]@{
  version   = $ver
  notes     = $Notes
  pub_date  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  platforms = [ordered]@{
    "windows-x86_64" = [ordered]@{
      signature = $sig.Trim()
      url       = "https://github.com/$Repo/releases/download/$tag/$asset"
    }
  }
}
$json = $manifest | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText((Join-Path $out "latest.json"), $json, (New-Object Text.UTF8Encoding $false))

[IO.File]::WriteAllText((Join-Path $out "notes.md"), $Notes, (New-Object Text.UTF8Encoding $false))
$ghArgs = @("release", "create", $tag, (Join-Path $out $asset), (Join-Path $out "latest.json"),
  "-R", $Repo, "--title", "Ghost Monitor $ver", "--notes-file", (Join-Path $out "notes.md"), "--target", "main")
if ($Draft) { $ghArgs += "--draft" }
gh @ghArgs
if ($LASTEXITCODE) { throw "gh release create failed" }
Write-Output "published $tag"
