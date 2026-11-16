; SecretSpace sync server installer for Windows - compiled by builder\build.py
; with Inno Setup 6:
;     ISCC.exe /DAppVersion=2.3.0 installer\SecretSpace-Server.iss
;
; Separate from SecretSpace-Client-Installer.exe (the app): either can be
; installed, run and uninstalled without the other, on the same PC or on
; different ones.
;
; Installs for the whole machine (it needs administrator rights) into
; Program Files\SecretSpace Server two programs: SecretSpace-Server.exe, the server,
; and SecretSpace-Server-Setup.exe, which changes its settings. At the end it
; runs SecretSpace-Server-Setup.exe in a console window, which asks for the
; network and port and creates:
;   - %ProgramData%\SecretSpace Server\  sync.env, token, store\, logs\
;   - a Windows Firewall rule (group "SecretSpace Sync Server")
;   - a Task Scheduler task "SecretSpace Sync Server" that starts the server
;     at boot as LOCAL SERVICE
; An upgrade keeps the saved network and port without asking. Uninstalling
; removes the task and the firewall rule and KEEPS %ProgramData%\SecretSpace
; Server, because that is where the vaults are.
;
; An install from before the rename (PassMan Server, up to 2.0.0) is upgraded
; in place - same AppId. Its two programs and its Start Menu folder are
; removed here; the setup step then moves %ProgramData%\PassMan Server to
; the current name and replaces the old task and firewall rules. The port,
; the token and the vaults are not changed.
;
; Silent install, e.g. for testing:
;     SecretSpace-Server-Installer.exe /VERYSILENT /SUPPRESSMSGBOXES /HOST=0.0.0.0 /PORT=8787

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
; Four plain numbers: a test version's AppVersion (2.0.0-alpha.1) is not
; one, so the builder passes 2.0.0.1 here as well.
#ifndef FileVersion
  #define FileVersion "0.0.0.0"
#endif

[Setup]
; Never change AppId: it is how an upgrade finds the copy it replaces. It is
; not the app's AppId, so the two never replace each other.
AppId={{6C1E2B7A-5F3D-4C8E-9A41-2D7B0E93F615}
AppName=SecretSpace Server
AppVersion={#AppVersion}
AppVerName=SecretSpace Server {#AppVersion}
VersionInfoVersion={#FileVersion}
DefaultDirName={autopf}\SecretSpace Server
DisableProgramGroupPage=yes
PrivilegesRequired=admin
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..
OutputBaseFilename=SecretSpace-Server-Installer
SetupIconFile=..\server\SecretSpace-logo.ico
UninstallDisplayIcon={app}\SecretSpace-Server.exe
UninstallDisplayName=SecretSpace Server
WizardStyle=modern
; The pictures come from make_wizard_images.py: 100%, 150% and 200% scaling.
WizardImageFile=wizard-large-100.bmp,wizard-large-150.bmp,wizard-large-200.bmp
WizardSmallImageFile=wizard-small-100.bmp,wizard-small-150.bmp,wizard-small-200.bmp
; The GPL needs no "I accept": a page that says what it allows, and the
; full text installed beside the program.
InfoBeforeFile=licence-notice.txt
Compression=lzma2
SolidCompression=yes

[InstallDelete]
; An upgrade must not leave the previous version's libraries behind.
Type: filesandordirs; Name: "{app}\_internal"
; Nor what an install from before the rename left: its Start Menu folder
; and its two programs (the libraries above are shared and replaced).
Type: filesandordirs; Name: "{autoprograms}\PassMan Server"
Type: files; Name: "{app}\PassMan-Server.exe"
Type: files; Name: "{app}\PassMan-Server-Setup.exe"

[Files]
Source: "..\build\server\SecretSpace-Server\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\SecretSpace Server\Change network or port"; Filename: "{app}\SecretSpace-Server-Setup.exe"; Parameters: "--pause setup"
Name: "{autoprograms}\SecretSpace Server\Show the token"; Filename: "{app}\SecretSpace-Server-Setup.exe"; Parameters: "--pause show-token"
Name: "{autoprograms}\SecretSpace Server\Turn HTTPS on"; Filename: "{app}\SecretSpace-Server-Setup.exe"; Parameters: "--pause tls"
Name: "{autoprograms}\SecretSpace Server\Replace the token"; Filename: "{app}\SecretSpace-Server-Setup.exe"; Parameters: "--pause new-token"
Name: "{autoprograms}\SecretSpace Server\Server log"; Filename: "{commonappdata}\SecretSpace Server\logs\server.log"

[Run]
; Upgrade: same network and port, task re-pointed at this copy, restarted.
Filename: "{app}\SecretSpace-Server-Setup.exe"; Parameters: "setup --keep"; StatusMsg: "Restarting the server..."; Flags: runhidden waituntilterminated; Check: IsUpgrade
; First install, silent: the /HOST= and /PORT= given, else every network on 8787.
Filename: "{app}\SecretSpace-Server-Setup.exe"; Parameters: "setup --host {param:HOST|0.0.0.0} --port {param:PORT|8787}"; StatusMsg: "Setting up the server..."; Flags: runhidden waituntilterminated; Check: FirstSilentInstall
; First install: the questions, in a console window.
Filename: "{app}\SecretSpace-Server-Setup.exe"; Parameters: "--pause setup"; StatusMsg: "Setting up the server - answer the questions in the console window..."; Flags: waituntilterminated; Check: FirstInteractiveInstall

[UninstallRun]
; Same RunOnceId as before the split, so an upgraded install runs this once.
Filename: "{app}\SecretSpace-Server-Setup.exe"; Parameters: "remove"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveTaskAndFirewall"

[Code]
var
  WasInstalled: Boolean;

function ConfigFile: String;
begin
  Result := ExpandConstant('{commonappdata}\SecretSpace Server\sync.env');
end;

{ Where an install from before the rename keeps its settings. Only looked
  for, never written: the setup step moves that folder to the current name. }
function OldConfigFile: String;
begin
  Result := ExpandConstant('{commonappdata}\PassMan Server\sync.env');
end;

{ Decided before anything runs: the first-install setup creates sync.env,
  which must not turn the entries after it into upgrade ones. }
function InitializeSetup: Boolean;
begin
  WasInstalled := FileExists(ConfigFile) or FileExists(OldConfigFile);
  Result := True;
end;

function IsUpgrade: Boolean;
begin
  Result := WasInstalled;
end;

function FirstSilentInstall: Boolean;
begin
  Result := (not WasInstalled) and WizardSilent;
end;

function FirstInteractiveInstall: Boolean;
begin
  Result := (not WasInstalled) and not WizardSilent;
end;

{ The running server holds its files open: stop it before replacing them.
  Setup starts it again afterwards. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "SecretSpace Sync Server"',
       '', SW_HIDE, ewWaitUntilTerminated, Code);
  { The task of an install from before the rename. }
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "PassMan Sync Server"',
       '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(1000);
  Result := '';
end;

{ The uninstaller is about to delete the program: stop the server first. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
begin
  if CurUninstallStep = usUninstall then
    Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "SecretSpace Sync Server"',
         '', SW_HIDE, ewWaitUntilTerminated, Code);
end;
