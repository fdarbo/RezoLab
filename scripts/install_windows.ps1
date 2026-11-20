# RézoLab — installateur Windows (PowerShell 5.1+). Lancez install_windows.bat
$ErrorActionPreference = 'Stop'
function Ok($m)   { Write-Host "[OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[ATTENTION] $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "[ECHEC] $m" -ForegroundColor Red; Read-Host "Appuyez sur Entrée pour quitter"; exit 1 }

# Recherche de rezolab.py : a cote du script, dans .\rezolab, puis dans le dossier parent (scripts\ -> racine du projet)
$here = $PSScriptRoot; $app = $null; $root = $null
foreach ($base in @($here, (Split-Path $here -Parent))) {
    foreach ($d in @($base, (Join-Path $base 'rezolab'))) {
        if (-not $app -and (Test-Path (Join-Path $d 'rezolab.py'))) { $app = $d; $root = $base }
    }
}
if (-not $app) { Fail "rezolab.py introuvable (cherché près de $here et dans le dossier parent)." }
Set-Location -LiteralPath $root
$req = 'requirements.txt'; if (-not (Test-Path $req)) { $req = Join-Path $app 'requirements.txt' }
if (-not (Test-Path $req)) { Fail "requirements.txt introuvable (cherché dans $root et $app)." }

# 1. Python 3.8+ (lanceur « py » ou « python »)
function Test-Py($exe, $a) {
    try { $v = & $exe @a --version 2>&1; return (($v -match 'Python 3\.(\d+)') -and ([int]$Matches[1] -ge 8)) } catch { return $false }
}
$pyExe = $null; $pyArgs = @()
if (Test-Py 'py' @('-3'))      { $pyExe = 'py'; $pyArgs = @('-3') }
elseif (Test-Py 'python' @())  { $pyExe = 'python' }
if (-not $pyExe) {
    Warn "Python 3.8+ introuvable."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $r = Read-Host "Installer Python 3.12 avec winget ? [O/n]"
        if ($r -eq '' -or $r -match '^[OoYy]') {
            winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
            Warn "Python installé. FERMEZ cette fenêtre puis relancez install_windows.bat (le PATH doit être rechargé)."
            Read-Host "Appuyez sur Entrée pour quitter"; exit 0
        }
    }
    Fail "Installez Python depuis https://www.python.org/downloads/ (cochez « Add python.exe to PATH »), puis relancez."
}
Ok ("Python : " + (& $pyExe @pyArgs --version))

# 2. Environnement virtuel + dépendances
if (-not (Test-Path '.venv\Scripts\python.exe')) {
    Write-Host "[*] Création de l'environnement virtuel ..."
    & $pyExe @pyArgs -m venv .venv
    if ($LASTEXITCODE -ne 0) { Fail "Création du venv impossible." }
}
$venvPy = Join-Path $root '.venv\Scripts\python.exe'
& $venvPy -m pip install --quiet --upgrade pip
& $venvPy -m pip install --quiet -r $req
if ($LASTEXITCODE -ne 0) { Fail "Installation de scapy impossible (connexion Internet ?)." }
& $venvPy -c "from scapy.all import AsyncSniffer, srp, sr, Ether, conf"
if ($LASTEXITCODE -ne 0) { Fail "scapy installé mais inutilisable." }
Ok "scapy installé"

# 3. Npcap : pilote de capture indispensable sous Windows
$npcap = (Test-Path "$env:SystemRoot\System32\Npcap") -or (Get-Service -Name npcap -ErrorAction SilentlyContinue)
if ($npcap) { Ok "Npcap détecté" }
else {
    Warn "Npcap n'est pas installé : sans lui, la capture et le scan sont impossibles."
    Warn "Installez-le (cochez « Install Npcap in WinPcap API-compatible Mode »), puis relancez RézoLab."
    Start-Process 'https://npcap.com/#download'
}

# 4. Raccourci sur le Bureau (lance run_windows.bat, qui demande les droits administrateur)
try {
    $lnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'RezoLab.lnk'
    $s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
    $s.TargetPath = Join-Path $PSScriptRoot 'run_windows.bat'
    $s.WorkingDirectory = $root
    $s.IconLocation = 'shell32.dll,18'
    $s.Save()
    Ok "Raccourci créé sur le Bureau : RezoLab"
} catch { Warn "Raccourci non créé ($($_.Exception.Message)). Lancez run_windows.bat." }

Write-Host ""
Write-Host "Installation terminée. Lancez RézoLab avec le raccourci du Bureau ou run_windows.bat," -ForegroundColor Green
Write-Host "puis ouvrez http://127.0.0.1:8420"
Read-Host "Appuyez sur Entrée pour quitter"
