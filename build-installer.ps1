$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$exePath = Join-Path $projectRoot 'target\release\rustvault.exe'

if (-not (Test-Path $exePath)) {
    Write-Error "Release build not found at $exePath. Run: cargo build --release"
    exit 1
}

if (-not (Get-Command "wix" -ErrorAction SilentlyContinue)) {
    Write-Host "WiX not found on PATH. Install WiX Toolset or create a manual installer script." -ForegroundColor Yellow
    exit 0
}

$installerDir = Join-Path $projectRoot 'installer'
New-Item -ItemType Directory -Force -Path $installerDir | Out-Null

$wxsPath = Join-Path $installerDir 'rustvault.wxs'
@'
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="*" Name="RustVault" Language="1033" Version="1.0.0.0" Manufacturer="RustVault" UpgradeCode="{8F3E9200-6A4A-4C0B-A6CB-8E8E1F23A01D}">
        <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine" />
        <MediaTemplate />
        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="ProgramFilesFolder">
                <Directory Id="INSTALLFOLDER" Name="RustVault" />
            </Directory>
        </Directory>
        <DirectoryRef Id="INSTALLFOLDER">
            <Component Id="RustVaultExe" Guid="{5A9E5E84-0F4E-4D66-8BE3-34C3D99C5F4E}">
                <File Id="RustVaultExeFile" Source="C:\\path\\to\\rustvault.exe" KeyPath="yes" />
            </Component>
        </DirectoryRef>
        <Feature Id="MainFeature" Title="RustVault" Level="1">
            <ComponentRef Id="RustVaultExe" />
        </Feature>
    </Product>
</Wix>
'@ | Set-Content -Path $wxsPath -Encoding UTF8

Write-Host "Installer scaffold created at $wxsPath" -ForegroundColor Green
Write-Host "Update the Source path to the built exe before running wix build." -ForegroundColor Yellow
