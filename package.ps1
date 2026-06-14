param(
    [ValidateSet("installer", "stage", "clean")]
    [string]$Mode = "installer",
    [string]$BuildType = "Release"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $ScriptDir "build-release"
$DistDir = Join-Path $ScriptDir "dist\windows"
$StageDir = Join-Path $DistDir "stage"
$ExecutableName = "warden-free.exe"
$NsisScript = Join-Path $ScriptDir "packaging\windows\installer.nsi"
$IconPath = Join-Path $ScriptDir "assets\Warden-Logo-Transparent.ico"

function Write-Status($Message) {
    Write-Host "[PACKAGE] $Message" -ForegroundColor Cyan
}

function Write-ProgressMessage($Message) {
    Write-Host "[PACKAGE] $Message" -ForegroundColor Yellow
}

function Write-Success($Message) {
    Write-Host "[PACKAGE] $Message" -ForegroundColor Green
}

function Require-Command($Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

function Configure-Release {
    Write-ProgressMessage "Configuring Release build in $BuildDir"
    cmake -S $ScriptDir -B $BuildDir -DCMAKE_BUILD_TYPE=$BuildType
}

function Build-Release {
    Configure-Release
    Write-ProgressMessage "Building Warden Free"
    cmake --build $BuildDir --config $BuildType
}

function Stage-Files {
    Build-Release
    Require-Command "windeployqt"

    if (Test-Path $StageDir) {
        Remove-Item -Recurse -Force $StageDir
    }

    New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

    Write-ProgressMessage "Installing staged files into $StageDir"
    cmake --install $BuildDir --config $BuildType --prefix $StageDir

    $ExePath = Join-Path $StageDir $ExecutableName
    if (-not (Test-Path $ExePath)) {
        throw "Expected staged executable not found: $ExePath"
    }

    Write-ProgressMessage "Deploying Qt runtime with windeployqt"
    windeployqt --release $ExePath

    Write-Success "Windows staging ready: $StageDir"
}

function Build-Installer {
    Stage-Files
    Require-Command "makensis"

    $OutputExe = Join-Path $DistDir "warden-free-$BuildType-installer.exe"
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

    Write-ProgressMessage "Building NSIS installer"
    & makensis `
        "/DAPP_NAME=Warden Free" `
        "/DAPP_ID=warden-free" `
        "/DPRIMARY_EXE=$ExecutableName" `
        "/DSTAGE_DIR=$StageDir" `
        "/DOUTPUT_EXE=$OutputExe" `
        "/DICON_PATH=$IconPath" `
        $NsisScript

    Write-Success "Installer ready: $OutputExe"
}

function Clean-Outputs {
    Write-ProgressMessage "Removing $BuildDir and $DistDir"
    Remove-Item -Recurse -Force $BuildDir, $DistDir -ErrorAction SilentlyContinue
    Write-Success "Packaging outputs removed."
}

switch ($Mode) {
    "installer" { Build-Installer }
    "stage" { Stage-Files }
    "clean" { Clean-Outputs }
}
