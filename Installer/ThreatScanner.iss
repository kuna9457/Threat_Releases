; Inno Setup script for URL Threat Scanner
;
; Packages BOTH executables from Threat_Backend\dist\ThreatScanner\:
;   ThreatScanner.exe     — Windowed GUI (primary; Desktop + Start Menu shortcuts)
;   ThreatScanner_CLI.exe — Console CLI  (installed alongside; no shortcut)
;
; Installs per-user (no admin rights needed).

#define MyAppName      "URL Threat Scanner"
#define MyAppVersion   ReadIni("..\Threat_Backend\version.ini", "Settings", "Version", "1.0.0")
#define MyAppPublisher "Kunal"
#define MyAppExeName   "ThreatScanner.exe"       ; GUI — what shortcuts open
#define MyAppCLIName   "ThreatScanner_CLI.exe"   ; CLI — accessible from install dir
#define SourceDir      "..\Threat_Backend\dist\ThreatScanner"

[Setup]
AppId={{B6C1D9F0-6B1E-4E2A-9C3E-3E7B5D0F1A22}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\ThreatScanner
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=.
OutputBaseFilename=ThreatScanner_Setup
SetupIconFile=app_icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}
ArchitecturesInstallIn64BitMode=x64compatible
; Allow silent install (used by the auto-updater)
; /VERYSILENT /SP- /NORESTART

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"

[Files]
; Bundle every file from the dist folder (both .exe files are included here)
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; ── Start Menu ──────────────────────────────────────────────────────────────
; Primary shortcut → GUI
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
; Uninstall entry
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

; ── Desktop ──────────────────────────────────────────────────────────────────
; Desktop icon → GUI (optional task chosen during install)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

; NOTE: ThreatScanner_CLI.exe has NO shortcut — users who want CLI access
; can run it directly from the install directory:
;   %LocalAppData%\ThreatScanner\ThreatScanner_CLI.exe

[Run]
; Launch the GUI after installation finishes
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName} now"; Flags: nowait postinstall skipifsilent runascurrentuser
