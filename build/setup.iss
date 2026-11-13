; Display strings and the identity come from ISCC /D defines set by the build.
; The defaults are the ulrmm identity. Another AppId, program directory, exe or
; service name makes a separate product that cannot update an install in place.
#ifndef MyAppName
  #define MyAppName "UniversalLocal RMM Agent"
#endif
#ifndef MyAppVersion
  #define MyAppVersion "1.13.11.2026"
#endif
; file version is four numbers max: YYYY.M.D.X
#ifndef MyAppNumVersion
  #define MyAppNumVersion "2026.10.27.1"
#endif
#ifndef MyAppPublisher
  #define MyAppPublisher "UniversalLocal RMM"
#endif
#ifndef MyAppURL
  #define MyAppURL ""
#endif
#ifndef MyAppExeName
  #define MyAppExeName "ulrmm-agent.exe"
#endif
#ifndef MyAppSvcName
  #define MyAppSvcName "ulrmm-agent"
#endif
#ifndef MyAppProgDir
  #define MyAppProgDir "ULRMM Agent"
#endif
#ifndef MyAppId
  #define MyAppId "{{61D095D9-C6CE-4D60-B192-4C6699822C40}"
#endif
; the agent's registry key under HKLM\SOFTWARE, holds the uninstall code
#ifndef MyAppRegKey
  #define MyAppRegKey "UniversalLocalRMM"
#endif
#define MESHEXE "meshagent.exe"
#define MESHDIR "{sd}\Program Files\Mesh Agent"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion=v{#MyAppVersion}
AppVerName={#MyAppName}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName="{sd}\Program Files\{#MyAppProgDir}"
DisableDirPage=yes
SetupLogging=yes
DisableProgramGroupPage=yes
#if FileExists(AddBackslash(SourcePath) + "brand.ico")
SetupIconFile=brand.ico
#endif
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
RestartApplications=no
CloseApplications=no
MinVersion=10.0
VersionInfoVersion={#MyAppNumVersion}
VersionInfoProductTextVersion=v{#MyAppVersion}
VersionInfoOriginalFileName={#MyAppExeName}
AppCopyright="Copyright (C) 2026 {#MyAppPublisher}"

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\agent.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion;
Source: "..\LICENSE.md"; DestDir: "{app}"; Flags: ignoreversion;
Source: "..\NOTICE.md"; DestDir: "{app}"; Flags: ignoreversion;
Source: "..\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion;

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "-m cleanup"; RunOnceId: "cleanuprm";
Filename: "{cmd}"; Parameters: "/c taskkill /F /IM {#MyAppExeName}"; RunOnceId: "killagent";
Filename: "{app}\{#MESHEXE}"; Parameters: "-fulluninstall"; RunOnceId: "meshrm";

[UninstallDelete]
Type: filesandordirs; Name: "{app}";
Type: filesandordirs; Name: "{#MESHDIR}";

[Code]
var
  AgentWasConfigured: Boolean;

// The agent writes its registry key when it registers with the server.
function AgentConfigured(): Boolean;
begin
  Result := RegKeyExists(HKLM, 'SOFTWARE\{#MyAppRegKey}');
  if not Result and IsWin64 then
    Result := RegKeyExists(HKLM64, 'SOFTWARE\{#MyAppRegKey}');
end;

function InitializeSetup(): boolean;
var
  ResultCode: Integer;
begin
  AgentWasConfigured := AgentConfigured();

  Exec('cmd.exe', '/c ping 127.0.0.1 -n 2 && net stop {#MyAppSvcName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('Stop service: ' + IntToStr(ResultCode));

  Exec('cmd.exe', '/c taskkill /F /IM {#MyAppExeName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('taskkill: ' + IntToStr(ResultCode));

  Result := True;
end;

// A setup made for a deployment carries signed enrollment data at its end:
// on a machine without an agent, the agent reads it from this setup file and
// registers itself. Exit code 3: a generic setup without that data.
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  Params: String;
begin
  if (CurStep <> ssPostInstall) or AgentWasConfigured then
    exit;
  Params := '-m install -enroll "' + ExpandConstant('{srcexe}') + '"';
  if WizardSilent then
    Params := Params + ' -silent';
  if not Exec(ExpandConstant('{app}\{#MyAppExeName}'), Params, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('enroll: the agent did not start: ' + SysErrorMessage(ResultCode))
  else if ResultCode = 3 then
    Log('enroll: no enrollment data in this setup')
  else
    Log('enroll: exit code ' + IntToStr(ResultCode));
end;

procedure DeinitializeSetup();
var
  ResultCode: Integer;
  WorkingDir:   String;
begin

  // After an enrollment the service exists and runs: installsvc then does
  // nothing (exit 0) and net start answers 2, both only logged.
  WorkingDir := ExpandConstant('{sd}\Program Files\{#MyAppProgDir}');
  Exec('cmd.exe', ' /c {#MyAppExeName} -m installsvc', WorkingDir, SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('install service: ' + IntToStr(ResultCode));

  // The display text follows the branding on every install, so existing
  // agents pick up a changed name with their next update.
  Exec('cmd.exe', '/c sc config {#MyAppSvcName} DisplayName= "{#MyAppName} Service"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('sc config DisplayName: ' + IntToStr(ResultCode));

  Exec('cmd.exe', '/c sc description {#MyAppSvcName} "{#MyAppName} Service"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('sc description: ' + IntToStr(ResultCode));

  Exec('cmd.exe', '/c net start {#MyAppSvcName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('Start service: ' + IntToStr(ResultCode));
end;

// The agent writes a random code at install and the server keeps it. Without
// it (/UNINSTALLCODE=<code> or ULRMM_UNINSTALL_CODE) the uninstall stops here.
// Once the service keeps the code encrypted, UninstallCodeSum is its SHA-256.
function StoredUninstallValue(Name: String): String;
var
  V: String;
begin
  V := '';
  if IsWin64 then
    RegQueryStringValue(HKLM64, 'SOFTWARE\{#MyAppRegKey}', Name, V);
  if V = '' then
    RegQueryStringValue(HKLM, 'SOFTWARE\{#MyAppRegKey}', Name, V);
  Result := V;
end;

function UninstallCodeOk(Stored, Sum, Given: String): Boolean;
begin
  if Sum <> '' then
    Result := (Given <> '') and (CompareText(GetSHA256OfString(Given), Sum) = 0)
  else
    Result := Given = Stored;
end;

function InitializeUninstall(): Boolean;
var
  Stored, Given: String;
begin
  Stored := StoredUninstallValue('UninstallCode');
  if Stored <> '' then
  begin
    Given := ExpandConstant('{param:UNINSTALLCODE|}');
    if Given = '' then
      Given := GetEnv('ULRMM_UNINSTALL_CODE');
    if not UninstallCodeOk(Stored, StoredUninstallValue('UninstallCodeSum'), Given) then
    begin
      Log('Uninstall refused: missing or wrong uninstall code');
      if not UninstallSilent then
        MsgBox('This agent is protected. Uninstall it from the dashboard, or run the uninstaller with /UNINSTALLCODE=<code>.', mbError, MB_OK);
      Result := False;
      exit;
    end;
  end;
  Result := True;
end;

// After the confirmation, before [UninstallRun] and the file removal, so a
// cancelled uninstall changes nothing. The self-heal task goes first: while
// the config is still there it would register a missing service again.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep <> usUninstall then
    exit;

  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "{#MyAppSvcName}-selfheal"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "{#MyAppSvcName}-selfheal" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('delete self-heal task: ' + IntToStr(ResultCode));

  Exec('cmd.exe', '/c ping 127.0.0.1 -n 2 && net stop {#MyAppSvcName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('cmd.exe', '/c taskkill /F /IM {#MyAppExeName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  Exec('cmd.exe', '/c sc delete {#MyAppSvcName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('delete service: ' + IntToStr(ResultCode));
end;
