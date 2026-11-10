; SecretSpace sync server installer for Windows - compiled by builder\build.py
; with Inno Setup 6:
;     ISCC.exe /DAppVersion=2.3.0 installer\SecretSpace-Server.iss
;
; Separate from SecretSpace-Client-Installer.exe (the app): either can be
; installed, run and uninstalled without the other, on the same PC or on
; different ones.
;
; Installs for the whole machine (it needs administrator rights) into
; Program Files\SecretSpace Server two programs: PassMan-Server.exe, the server,
; and PassMan-Server-Setup.exe, which changes its settings. At the end it
; runs PassMan-Server-Setup.exe in a console window, which asks for the
; network and port and creates:
;   - %ProgramData%\PassMan Server\  sync.env, token, store\, logs\
;   - a Windows Firewall rule (group "PassMan Sync Server")
;   - a Task Scheduler task "PassMan Sync Server" that starts the server
;     at boot as LOCAL SERVICE
; An upgrade keeps the saved network and port without asking. Uninstalling
; removes the task and the firewall rule and KEEPS %ProgramData%\SecretSpace
; Server, because that is where the vaults are.
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
SetupIconFile=..\server\PassMan-logo.ico
UninstallDisplayIcon={app}\PassMan-Server.exe
UninstallDisplayName=SecretSpace Server
WizardStyle=modern
Compression=lzma2
SolidCompression=yes

[InstallDelete]
; An upgrade must not leave the previous version's libraries behind.
Type: filesandordirs; Name: "{app}\_internal"
; Nor the Start Menu folder of the name before SecretSpace.
Type: filesandordirs; Name: "{autoprograms}\PassMan Server"

[Files]
Source: "..\build\server\PassMan-Server\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\SecretSpace Server\Change network or port"; Filename: "{app}\PassMan-Server-Setup.exe"; Parameters: "--pause setup"
Name: "{autoprograms}\SecretSpace Server\Show the token"; Filename: "{app}\PassMan-Server-Setup.exe"; Parameters: "--pause show-token"
Name: "{autoprograms}\SecretSpace Server\Replace the token"; Filename: "{app}\PassMan-Server-Setup.exe"; Parameters: "--pause new-token"
Name: "{autoprograms}\SecretSpace Server\Server log"; Filename: "{commonappdata}\PassMan Server\logs\server.log"

[Run]
; Upgrade: same network and port, task re-pointed at this copy, restarted.
Filename: "{app}\PassMan-Server-Setup.exe"; Parameters: "setup --keep"; StatusMsg: "Restarting the server..."; Flags: runhidden waituntilterminated; Check: IsUpgrade
; First install, silent: the /HOST= and /PORT= given, else every network on 8787.
Filename: "{app}\PassMan-Server-Setup.exe"; Parameters: "setup --host {param:HOST|0.0.0.0} --port {param:PORT|8787}"; StatusMsg: "Setting up the server..."; Flags: runhidden waituntilterminated; Check: FirstSilentInstall
; First install: the questions, in a console window.
Filename: "{app}\PassMan-Server-Setup.exe"; Parameters: "--pause setup"; StatusMsg: "Setting up the server - answer the questions in the console window..."; Flags: waituntilterminated; Check: FirstInteractiveInstall

[UninstallRun]
; Same RunOnceId as before the split, so an upgraded install runs this once.
Filename: "{app}\PassMan-Server-Setup.exe"; Parameters: "remove"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveTaskAndFirewall"

[Code]
var
  WasInstalled: Boolean;

function ConfigFile: String;
begin
  Result := ExpandConstant('{commonappdata}\PassMan Server\sync.env');
end;

{ Decided before anything runs: the first-install setup creates sync.env,
  which must not turn the entries after it into upgrade ones. }
function InitializeSetup: Boolean;
begin
  WasInstalled := FileExists(ConfigFile);
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
    Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "PassMan Sync Server"',
         '', SW_HIDE, ewWaitUntilTerminated, Code);
end;
