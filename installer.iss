; Inno Setup 6 script. Build the app first (build.ps1), then compile this file.
#define AppName "Gatekeeper"
#define AppVersion "0.1.0"
#define AppOwner "saimumadi00-sketch"
#define AppURL "https://github.com/saimumadi00-sketch/decLock"

[Setup]
AppId={{B7C1D3A2-5E4F-4A8B-9C61-2F0E7D9A1B34}
AppName={#AppName}
AppVersion={#AppVersion}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
PrivilegesRequired=admin
OutputDir=installer
OutputBaseFilename=GatekeeperSetup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName={#AppName}
; Ownership and the licence agreement (the user must accept it before installing).
AppPublisher={#AppOwner}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppCopyright=Copyright (C) 2026 {#AppOwner}. All rights reserved.
LicenseFile=LICENSE.txt
VersionInfoCompany={#AppOwner}
VersionInfoCopyright=Copyright (C) 2026 {#AppOwner}
VersionInfoDescription={#AppName} Setup
VersionInfoVersion={#AppVersion}

[Files]
Source: "dist\gatekeeper\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "THIRD_PARTY_NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "docs\LIMITATIONS.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "docs\USAGE.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Dirs]
; Enrolment markers (see gatekeeper/enrolment.py). The first [Run] entry locks its access list down.
Name: "{commonappdata}\{#AppName}\enrolled"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Icons]
; The desktop app is also the guard. Start it minimized at logon for every user (protection
; runs while the window sits in the taskbar). --service marks this as the installed copy,
; which makes dev mode impossible.
Name: "{commonstartup}\{#AppName}"; Filename: "{app}\gatekeeperw.exe"; Parameters: "--service gui --minimized"
Name: "{group}\{#AppName}"; Filename: "{app}\gatekeeperw.exe"; Parameters: "--service gui"
Name: "{commondesktop}\{#AppName}"; Filename: "{app}\gatekeeperw.exe"; Parameters: "--service gui"; Tasks: desktopicon
Name: "{group}\{#AppName} command prompt"; Filename: "{cmd}"; Parameters: "/k ""cd /d ""{app}"" && gatekeeper.exe --help"""

[Run]
; Enrolment folder access list: SYSTEM and Administrators get full control. Users may only list the
; folder and ADD files (WD = add file; no delete, no subfolders). Files added there are read-only to
; everyone but admins, and OWNER RIGHTS (S-1-3-4) takes away the creator's implicit right to change a
; file's permissions. So a standard user can record "I set Gatekeeper up" but never remove that record.
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\{#AppName}\enrolled"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(RX,WD) *S-1-5-32-545:(OI)(IO)R *S-1-3-4:(OI)(IO)R"; \
  Flags: runhidden waituntilterminated; StatusMsg: "Securing the enrolment folder..."
; First launch shows the "choose a password" screen inside the app.
Filename: "{app}\gatekeeperw.exe"; Parameters: "--service gui"; Description: "Open Gatekeeper now"; \
  Flags: postinstall nowait runasoriginaluser skipifsilent

[UninstallDelete]
; Uninstalling (admin only, and password-checked) clears the enrolment markers, so a reinstall starts fresh.
Type: filesandordirs; Name: "{commonappdata}\{#AppName}"

[UninstallRun]
; Stop the guard, un-freeze anything it left suspended, and undo the USB block so the
; machine is not left with a policy and no tool to manage it.
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM gatekeeperw.exe"; Flags: runhidden; RunOnceId: "StopGuard"
Filename: "{app}\gatekeeper.exe"; Parameters: "release"; Flags: runhidden; RunOnceId: "ReleaseApps"
Filename: "{sys}\reg.exe"; Parameters: "add HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR /v Start /t REG_DWORD /d 3 /f"; \
  Flags: runhidden; RunOnceId: "RestoreUsb"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  { Upgrade case: stop a running guard so its files can be replaced. }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM gatekeeperw.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  { Runs before anything is removed or stopped. Gatekeeper shows its password prompt and exits
    0 only for the right password (or when no password was ever set). Fails closed: if the
    check cannot run, nothing is uninstalled. Silent uninstalls (/SILENT) are checked too. }
  Result := Exec(ExpandConstant('{app}\gatekeeperw.exe'), '--service confirm-uninstall', '',
                 SW_SHOWNORMAL, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
  if not Result and not UninstallSilent then
    MsgBox('Gatekeeper was not uninstalled: the password was not confirmed.', mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    if not UninstallSilent then
      if MsgBox('Also delete your Gatekeeper settings, logs and face data for this Windows user?' + #13#10 +
                'This cannot be undone.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(ExpandConstant('{userappdata}\Gatekeeper'), True, True, True);
end;
