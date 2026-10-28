; Inno Setup 6 script. Build the app first (build.ps1), then compile this file.
#define AppName "Gatekeeper"
#define AppVersion "0.1.0"

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

[Files]
Source: "dist\gatekeeper\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "docs\LIMITATIONS.md"; DestDir: "{app}\docs"; Flags: ignoreversion

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
; First launch shows the "choose a password" screen inside the app.
Filename: "{app}\gatekeeperw.exe"; Parameters: "--service gui"; Description: "Open Gatekeeper now"; \
  Flags: postinstall nowait runasoriginaluser skipifsilent

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

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    if not UninstallSilent then
      if MsgBox('Also delete your Gatekeeper settings, logs and face data for this Windows user?' + #13#10 +
                'This cannot be undone.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(ExpandConstant('{userappdata}\Gatekeeper'), True, True, True);
end;
