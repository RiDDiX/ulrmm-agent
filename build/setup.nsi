; NSIS version of build/setup.iss, which stays as the fallback packer.
; Display strings and the identity come from makensis -D defines set by the
; build. The defaults are the ulrmm identity. Another AppId, program
; directory, exe or service name makes a separate product that cannot update
; an install in place.
; What the build (write_brand.py, build_agents.sh) does to every value:
; - control characters become a space and a run of whitespace one space;
;   removing the characters below can leave a space at either end
; - "$" is written as "$$", and a backslash that follows a "$" is removed:
;   makensis reads "$\r", "$\n" and "$\t" as control characters wherever a
;   define is expanded, also after a doubled "$"
; - backticks are removed: the script quotes values with them
; - braces and percent signs are removed: makensis expands ${name} and
;   $%NAME% in a value even after a doubled "$" (MyAppId keeps Inno's form
;   "{{GUID}" and is only checked)
; - quotes are removed: the values are quoted in the commands the setup runs
; The script doubles "&" for dialog labels itself. It stops the build when
; MyAppProgDir, MyAppExeName, MyAppSvcName, MyAppRegKey or MyAppId is empty
; or holds a single "$", or when MyAppProgDir or MyAppExeName holds "\", "/"
; or ":" or is only dots and spaces: each must name one entry directly below
; Program Files, and the uninstaller removes the program directory with
; everything in it. MyAppRegKey may hold "\" (a nested key).
!ifndef MyAppName
  !define MyAppName "UniversalLocal RMM Agent"
!endif
!ifndef MyAppVersion
  !define MyAppVersion "1.14.11.2026"
!endif
; file version is four numbers max: YYYY.M.D.X
!ifndef MyAppNumVersion
  !define MyAppNumVersion "2026.10.27.1"
!endif
!ifndef MyAppPublisher
  !define MyAppPublisher "UniversalLocal RMM"
!endif
!ifndef MyAppURL
  !define MyAppURL ""
!endif
!ifndef MyAppExeName
  !define MyAppExeName "ulrmm-agent.exe"
!endif
!ifndef MyAppSvcName
  !define MyAppSvcName "ulrmm-agent"
!endif
!ifndef MyAppProgDir
  !define MyAppProgDir "ULRMM Agent"
!endif
; same value as for Inno ("{{GUID}"): the uninstall key keeps Inno's name
; "{GUID}_is1", so an update over an Inno install rewrites that one entry
!ifndef MyAppId
  !define MyAppId "{{61D095D9-C6CE-4D60-B192-4C6699822C40}"
!endif
; the agent's registry key under HKLM\SOFTWARE, holds the uninstall code
!ifndef MyAppRegKey
  !define MyAppRegKey "UniversalLocalRMM"
!endif
!ifndef OutFile
  !define OutFile "Output/win.exe"
!endif

!macro RequireValue name
  !if `${${name}}` == ``
    !error `${name} must not be empty`
  !endif
  ; a "$" left after the doubled ones would be read as a variable
  !searchreplace _DOLLAR1 `${${name}}` `$$` ``
  !searchreplace _DOLLAR2 `${_DOLLAR1}` `$` ``
  !if `${_DOLLAR2}` != `${_DOLLAR1}`
    !error `${name} must write "$" as "$$"`
  !endif
  !undef _DOLLAR1
  !undef _DOLLAR2
!macroend
!macro RejectPart name part
  !searchreplace _REJECT `${${name}}` `${part}` ``
  !if `${_REJECT}` != `${${name}}`
    !error `${name} must not hold "${part}"`
  !endif
  !undef _REJECT
!macroend
; one entry directly below Program Files. Windows drops trailing dots and
; spaces, so a name of only those would be Program Files itself.
!macro RequireEntryName name
  !insertmacro RequireValue ${name}
  !insertmacro RejectPart ${name} `\`
  !insertmacro RejectPart ${name} `/`
  !insertmacro RejectPart ${name} `:`
  !searchreplace _ENTRY1 `${${name}}` `.` ``
  !searchreplace _ENTRY2 `${_ENTRY1}` ` ` ``
  !if `${_ENTRY2}` == ``
    !error `${name} must not be only dots and spaces`
  !endif
  !undef _ENTRY1
  !undef _ENTRY2
!macroend
!insertmacro RequireEntryName MyAppProgDir
!insertmacro RequireEntryName MyAppExeName
!insertmacro RequireValue MyAppSvcName
!insertmacro RequireValue MyAppRegKey
!insertmacro RequireValue MyAppId

!define MESHEXE "meshagent.exe"
!searchreplace APPGUID "${MyAppId}" "{{" "{"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPGUID}_is1"
; the agent looks for unins*.exe in its program dir (agent.go GetUninstallExe)
!define UNINST_EXE "unins000.exe"
; dialog labels read "&" as a shortcut key
!searchreplace NAMEDA `${MyAppName}` "&" "&&"
; OutFile and the version resource take "$$" as it is
!searchreplace OUTFILE `${OutFile}` "$$" "$"
!searchreplace VINAME `${MyAppName}` "$$" "$"
!searchreplace VIPUBLISHER `${MyAppPublisher}` "$$" "$"
!searchreplace VIEXE `${MyAppExeName}` "$$" "$"

Unicode true
ManifestSupportedOS all
RequestExecutionLevel admin
SetCompressor /SOLID lzma
CRCCheck on
Name `${MyAppName}` `${NAMEDA}`
OutFile `${OUTFILE}`
BrandingText " "
ShowInstDetails show
!if /FileExists "brand.ico"
  Icon "brand.ico"
  UninstallIcon "brand.ico"
!endif

VIProductVersion "${MyAppNumVersion}"
VIFileVersion "${MyAppNumVersion}"
VIAddVersionKey "ProductName" `${VINAME}`
VIAddVersionKey "CompanyName" `${VIPUBLISHER}`
VIAddVersionKey "FileDescription" `${VINAME} Setup`
VIAddVersionKey "FileVersion" "v${MyAppVersion}"
VIAddVersionKey "ProductVersion" "v${MyAppVersion}"
VIAddVersionKey "OriginalFilename" `${VIEXE}`
VIAddVersionKey "LegalCopyright" `Copyright (C) 2026 ${VIPUBLISHER}`

!include LogicLib.nsh
!include FileFunc.nsh
!include WordFunc.nsh
!include WinVer.nsh
!include x64.nsh

Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Var LogFile
Var AgentWasConfigured
Var Recovered
Var Rc
Var SysDrive

; Inno wrote a log with /LOG=<file>; this NSIS build has no LogSet, so
; lines go to the details view and, when asked for, to that file.
!macro Log msg
  DetailPrint `${msg}`
  ${If} $LogFile != ""
    FileWrite $LogFile `${msg}$\r$\n`
  ${EndIf}
!macroend

!macro CloseLog
  ${If} $LogFile != ""
    FileClose $LogFile
    StrCpy $LogFile ""
  ${EndIf}
!macroend

; Inno switches the agent, the server scripts and old installs pass:
; /VERYSILENT /SILENT /SUPPRESSMSGBOXES /NORESTART /LOG=<file>.
; Unknown switches are ignored. NSIS's own /S works too.
!macro ParseArgs un
  ${${un}GetParameters} $R0
  ClearErrors
  ${${un}GetOptions} $R0 "/VERYSILENT" $R1
  ${IfNot} ${Errors}
    SetSilent silent
  ${EndIf}
  ClearErrors
  ${${un}GetOptions} $R0 "/SILENT" $R1
  ${IfNot} ${Errors}
    SetSilent silent
  ${EndIf}
  ClearErrors
  ${${un}GetOptions} $R0 "/LOG=" $R1
  ; GetOptions skips quoted text, and Go quotes the whole argument
  ; ("/LOG=C:\dir with space\x.txt") when the path has a space
  ; testing the error flag clears it, and WordFind returns "1" when it finds
  ; nothing: $R1 takes a result only once it is valid
  ${If} ${Errors}
    StrCpy $R1 ""
    ${${un}WordFind} $R0 '"/LOG=' "E+1}" $R2
    ${IfNot} ${Errors}
      StrCpy $R1 $R2
      ${${un}WordFind} $R2 '"' "E+1{" $R3
      ${IfNot} ${Errors}
        StrCpy $R1 $R3
      ${EndIf}
    ${EndIf}
  ${EndIf}
  ${If} $R1 != ""
    FileOpen $LogFile $R1 w
  ${EndIf}
!macroend

; Inno's {sd}: the system drive, else the drive of the Windows directory.
; Only a drive letter and a colon count: the uninstaller hands paths on this
; drive to cmd.
!macro SysDrive un
Function ${un}SysDrive
  ReadEnvStr $SysDrive SYSTEMDRIVE
  StrCpy $R7 $SysDrive "" 1
  StrCpy $R8 $SysDrive 1
  ${If} $R7 S== ":"
    StrCpy $R9 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    ${Do}
      StrCpy $R7 $R9 1
      StrCpy $R9 $R9 "" 1
      ${If} $R7 == ""
        ${Break}
      ${EndIf}
    ${LoopUntil} $R7 S== $R8
  ${Else}
    StrCpy $R7 ""
  ${EndIf}
  ${If} $R7 == ""
    StrCpy $SysDrive $WINDIR 2
  ${EndIf}
  StrCpy $INSTDIR `$SysDrive\Program Files\${MyAppProgDir}`
FunctionEnd
!macroend
!insertmacro SysDrive ""
!insertmacro SysDrive "un."

; SOFTWARE\<RegKey> exists once the agent registered. 386 agents write the
; 32-bit view, amd64 agents the 64-bit view; check both like setup.iss.
Function AgentConfigured
  StrCpy $Rc 0
  ${If} ${RunningX64}
    SetRegView 64
    ClearErrors
    EnumRegValue $R9 HKLM `SOFTWARE\${MyAppRegKey}` 0
    ${IfNot} ${Errors}
      StrCpy $Rc 1
    ${EndIf}
    SetRegView 32
  ${EndIf}
  ClearErrors
  EnumRegValue $R9 HKLM `SOFTWARE\${MyAppRegKey}` 0
  ${IfNot} ${Errors}
    StrCpy $Rc 1
  ${EndIf}
  Push $Rc
FunctionEnd

; Windows looks for a bare program name in the setup's own folder and the
; current directory first; either can be writable (a download, the temp folder).
!macro Run cmd label
  nsExec::Exec `${cmd}`
  Pop $Rc
  !insertmacro Log `${label}: $Rc`
!macroend

; In: $1 the side file, $2 the target. Replaces the target in one step, so
; an interrupted write never leaves a half file under the target's name.
; A lock that ends within a few seconds (the old process still exiting, a
; scanner reading the new file) does not stop the update.
; Failed when $0 is 0 or the side file is still there.
Function ReplaceFile
  StrCpy $3 0
  ${Do}
    ; MOVEFILE_REPLACE_EXISTING=1 | MOVEFILE_WRITE_THROUGH=8
    System::Call 'kernel32::MoveFileExW(w r1, w r2, i 9) i .r0'
    IntOp $3 $3 + 1
    ${If} $0 <> 0
    ${OrIf} $3 >= 10
      ${Break}
    ${EndIf}
    Sleep 500
  ${Loop}
  ; shows how long locks last in the field
  ${If} $0 <> 0
  ${AndIf} $3 > 1
    !insertmacro Log "replace $2: done on try $3"
  ${EndIf}
FunctionEnd

; The service runs again on every way out once the setup stopped it:
; the old agent stops it right after starting this setup.
Function .onInit
  !insertmacro ParseArgs ""
  ${IfNot} ${AtLeastWin10}
    !insertmacro Log "Windows 10 or newer is required"
    MessageBox MB_ICONSTOP "Windows 10 or newer is required." /SD IDOK
    ; the same stop as the section first, else the old agent's own stop
    ; follows this start and the service stays down
    Sleep 1000 ; setup.iss pings for a second before net stop
    !insertmacro Run `"$SYSDIR\net.exe" stop "${MyAppSvcName}"` "Stop service"
    !insertmacro Run `"$SYSDIR\taskkill.exe" /F /IM "${MyAppExeName}"` "taskkill"
    !insertmacro Run `"$SYSDIR\net.exe" start "${MyAppSvcName}"` "Start service"
    !insertmacro CloseLog
    SetErrorLevel 1
    Abort
  ${EndIf}
  Call SysDrive
  Call AgentConfigured
  Pop $AgentWasConfigured
FunctionEnd

; Like Inno's DeinitializeSetup: after an enrollment the service exists and
; runs, installsvc then does nothing and net start answers 2, both logged.
Function PostInstall
  SetOutPath "$INSTDIR"
  !insertmacro Run `"$INSTDIR\${MyAppExeName}" -m installsvc` "install service"
  ; the display text follows the branding on every install
  !insertmacro Run `"$SYSDIR\sc.exe" config "${MyAppSvcName}" DisplayName= "${MyAppName} Service"` "sc config DisplayName"
  !insertmacro Run `"$SYSDIR\sc.exe" description "${MyAppSvcName}" "${MyAppName} Service"` "sc description"
  !insertmacro Run `"$SYSDIR\net.exe" start "${MyAppSvcName}"` "Start service"
  !insertmacro CloseLog
FunctionEnd

; A file could not be written: the old exe and uninstaller stay in place.
Function Recover
  ${If} $Recovered != 1
    StrCpy $Recovered 1
    Delete "$INSTDIR\${MyAppExeName}.new"
    Delete "$INSTDIR\${UNINST_EXE}.new"
    Call PostInstall
  ${EndIf}
FunctionEnd

; An interactive run calls .onInstFailed only when the window is closed,
; so the section recovers where it fails.
!macro Fail msg
  !insertmacro Log `${msg}`
  Call Recover
  Abort
!macroend

; An error the NSIS runtime raises itself (a file it cannot extract) shows its
; own box; in an interactive run the recovery follows when that window closes.
Function .onInstFailed
  Call Recover
FunctionEnd

; Inno's [Run] postinstall entry: the status window, not in silent mode.
Function .onInstSuccess
  ${IfNot} ${Silent}
    MessageBox MB_YESNO|MB_ICONQUESTION `Launch ${MyAppName}?` /SD IDNO IDNO done
    Exec `"$INSTDIR\${MyAppExeName}"`
    done:
  ${EndIf}
FunctionEnd

Section "Agent" SecAgent
  Sleep 1000 ; setup.iss pings for a second before net stop
  !insertmacro Run `"$SYSDIR\net.exe" stop "${MyAppSvcName}"` "Stop service"
  !insertmacro Run `"$SYSDIR\taskkill.exe" /F /IM "${MyAppExeName}"` "taskkill"

  SetOutPath "$INSTDIR"
  ; a file that cannot be written (a scanner holds it) sets the error flag
  ; instead of asking, in silent mode too
  SetOverwrite try
  ; no source file times in the setup: same inputs, same bytes
  SetDateSave off
  ; "try" leaves a read-only file as it is, and so does MoveFileEx
  SetFileAttributes "$INSTDIR\${MyAppExeName}.new" NORMAL
  SetFileAttributes "$INSTDIR\${MyAppExeName}" NORMAL
  SetFileAttributes "$INSTDIR\LICENSE.md" NORMAL
  SetFileAttributes "$INSTDIR\NOTICE.md" NORMAL
  SetFileAttributes "$INSTDIR\THIRD_PARTY_NOTICES.md" NORMAL
  SetFileAttributes "$INSTDIR\${UNINST_EXE}.new" NORMAL
  SetFileAttributes "$INSTDIR\${UNINST_EXE}" NORMAL
  ; a missing file sets the error flag
  ClearErrors
  File "/oname=${MyAppExeName}.new" "../agent.exe"
  File "../LICENSE.md"
  File "../NOTICE.md"
  File "../THIRD_PARTY_NOTICES.md"
  ${If} ${Errors}
    !insertmacro Fail "write files: failed"
  ${EndIf}
  StrCpy $1 "$INSTDIR\${MyAppExeName}.new"
  StrCpy $2 "$INSTDIR\${MyAppExeName}"
  Call ReplaceFile
  ${If} $0 == 0
  ${OrIf} ${FileExists} $1
    !insertmacro Fail "replace ${MyAppExeName}: failed"
  ${EndIf}

  ; Over an Inno install unins000.exe becomes this uninstaller in one step,
  ; so Inno's UninstallString points at a working uninstaller at every step.
  ClearErrors
  WriteUninstaller "$INSTDIR\${UNINST_EXE}.new"
  ${If} ${Errors}
    !insertmacro Fail "write uninstaller: failed"
  ${EndIf}
  StrCpy $1 "$INSTDIR\${UNINST_EXE}.new"
  StrCpy $2 "$INSTDIR\${UNINST_EXE}"
  Call ReplaceFile
  ${If} $0 == 0
  ${OrIf} ${FileExists} $1
    !insertmacro Fail "replace ${UNINST_EXE}: failed"
  ${EndIf}

  ; The setup is 32-bit, so HKLM\Software is the 32-bit view (WOW6432Node on
  ; 64-bit Windows). Inno's 32-bit install mode wrote its entry there too:
  ; the same key is rewritten and there is one entry. The values are written
  ; over the old ones, so the entry is there at every moment.
  SetRegView 32
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" `${MyAppName}`
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "v${MyAppVersion}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" `${MyAppPublisher}`
  WriteRegStr HKLM "${UNINST_KEY}" "URLInfoAbout" `${MyAppURL}`
  WriteRegStr HKLM "${UNINST_KEY}" "HelpLink" `${MyAppURL}`
  WriteRegStr HKLM "${UNINST_KEY}" "URLUpdateInfo" `${MyAppURL}`
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${MyAppExeName}"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR\"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" `"$INSTDIR\${UNINST_EXE}"`
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" `"$INSTDIR\${UNINST_EXE}" /VERYSILENT`
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  ${GetTime} "" "L" $3 $4 $5 $6 $7 $8 $9
  WriteRegStr HKLM "${UNINST_KEY}" "InstallDate" "$5$4$3"
  SectionGetSize ${SecAgent} $3
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" $3
  ; values only Inno wrote: "Inno Setup: ..." and the version numbers it
  ; derived, which would keep the old version
  StrCpy $3 0
  ${Do}
    ClearErrors
    EnumRegValue $4 HKLM "${UNINST_KEY}" $3
    ${If} ${Errors}
    ${OrIf} $4 == ""
      ${Break}
    ${EndIf}
    StrCpy $5 $4 10
    ClearErrors
    ${If} $5 == "Inno Setup"
      DeleteRegValue HKLM "${UNINST_KEY}" $4
    ${EndIf}
    ; a value that stays moves the index on, a deleted one does not
    ${If} $5 != "Inno Setup"
    ${OrIf} ${Errors}
      IntOp $3 $3 + 1
    ${EndIf}
  ${Loop}
  DeleteRegValue HKLM "${UNINST_KEY}" "MajorVersion"
  DeleteRegValue HKLM "${UNINST_KEY}" "MinorVersion"
  DeleteRegValue HKLM "${UNINST_KEY}" "VersionMajor"
  DeleteRegValue HKLM "${UNINST_KEY}" "VersionMinor"

  ; Inno's uninstall logs go only now, and an Inno unins001.exe the agent
  ; would prefer.
  Delete "$INSTDIR\unins0*.dat"
  Delete "$INSTDIR\unins0*.msg"
  Delete "$INSTDIR\unins001.exe"

  ; A setup made for a deployment carries signed enrollment data at its end:
  ; on a machine without an agent, the agent reads it from this setup file
  ; and registers itself. Exit code 3: a generic setup without that data.
  ${If} $AgentWasConfigured != 1
    StrCpy $R0 ""
    ${If} ${Silent}
      StrCpy $R0 " -silent"
    ${EndIf}
    nsExec::Exec `"$INSTDIR\${MyAppExeName}" -m install -enroll "$EXEPATH"$R0`
    Pop $Rc
    ${If} $Rc == 3
      !insertmacro Log "enroll: no enrollment data in this setup"
    ${Else}
      !insertmacro Log "enroll: exit code $Rc"
    ${EndIf}
  ${EndIf}
  Call PostInstall
SectionEnd

; ---- uninstall ----

; In: $0 a directory. Removes it with everything in it only when it is one
; plain name directly below <drive>\Program Files, wherever the uninstaller
; was started from; anything else stays and is logged.
Function un.RemoveDir
  StrCpy $1 `$SysDrive\Program Files\`
  StrLen $2 $1
  StrCpy $3 $0 $2
  StrCpy $5 1
  StrLen $6 $SysDrive
  StrCpy $7 $SysDrive 1 1
  ${If} $6 != 2
  ${OrIf} $7 != ":"
  ${OrIf} $3 != $1
    StrCpy $5 0
  ${EndIf}
  ; Windows drops trailing dots and spaces: a name of only those, or none,
  ; is Program Files itself. A quote anywhere would end the quoted path
  ; below, a line break the command line.
  StrCpy $9 0
  StrCpy $8 0
  ${DoWhile} $5 == 1
    StrCpy $6 $0 1 $8
    ${If} $6 == ""
      ${Break}
    ${EndIf}
    ${If} $6 == '"'
    ${OrIf} $6 == "$\r"
    ${OrIf} $6 == "$\n"
      StrCpy $5 0
    ${ElseIf} $8 < $2
      ; the prefix was compared above
    ${ElseIf} $6 == "\"
    ${OrIf} $6 == "/"
    ${OrIf} $6 == ":"
      StrCpy $5 0
    ${ElseIf} $6 != "."
      ${If} $6 != " "
        StrCpy $9 1
      ${EndIf}
    ${EndIf}
    IntOp $8 $8 + 1
  ${Loop}
  ${If} $9 != 1
    StrCpy $5 0
  ${EndIf}
  ${If} $5 == 1
    ; RMDir /r follows a junction and empties its target; rd removes the
    ; junction itself. cmd expands the variable once, so a "%" in the name
    ; stays as it is. Without the call a value from the caller's environment
    ; would be removed.
    StrCpy $6 0
    System::Call 'kernel32::SetEnvironmentVariableW(w "ULRMM_REMOVE_DIR", w r0) i .r6'
    ${If} $6 <> 0
      !insertmacro Run `"$SYSDIR\cmd.exe" /d /v:off /c rd /s /q "%ULRMM_REMOVE_DIR%"` "remove $0"
      ; rd ends with 0 also when a locked file keeps the directory
      ${If} ${FileExists} $0
        !insertmacro Log "still there: $0"
      ${Else}
        !insertmacro Log "removed: $0"
      ${EndIf}
    ${Else}
      !insertmacro Log "not removed, the environment could not be set: $0"
    ${EndIf}
  ${Else}
    !insertmacro Log "not removed, not a directory below Program Files: $0"
  ${EndIf}
FunctionEnd

; SHA-256 hex of an ANSI string with CryptoAPI (Inno: GetSHA256OfString).
; In: $0 the string. Out: $1 the lowercase hex, "" on error.
Function un.Sha256Hex
  StrCpy $1 ""
  StrLen $2 $0
  ; PROV_RSA_AES=24, CRYPT_VERIFYCONTEXT=0xF0000000, CALG_SHA_256=0x800C
  System::Call 'advapi32::CryptAcquireContextW(*p .r3, p 0, p 0, i 24, i 0xF0000000) i .r4'
  ${If} $4 == 0
    Return
  ${EndIf}
  System::Call 'advapi32::CryptCreateHash(p r3, i 0x800C, p 0, i 0, *p .r5) i .r4'
  ${If} $4 != 0
    System::Call 'advapi32::CryptHashData(p r5, m r0, i r2, i 0) i .r4'
    System::Alloc 32
    Pop $6
    ; HP_HASHVAL=2
    System::Call 'advapi32::CryptGetHashParam(p r5, i 2, p r6, *i 32, i 0) i .r4'
    ${If} $4 != 0
      ; CRYPT_STRING_HEXRAW=0xC | CRYPT_STRING_NOCRLF=0x40000000
      System::Call 'crypt32::CryptBinaryToStringW(p r6, i 32, i 0x4000000C, w .r1, *i ${NSIS_MAX_STRLEN}) i .r4'
    ${EndIf}
    System::Free $6
    System::Call 'advapi32::CryptDestroyHash(p r5)'
  ${EndIf}
  System::Call 'advapi32::CryptReleaseContext(p r3, i 0)'
FunctionEnd

; In: $0 value name. Out: $1 the value, 64-bit view first like setup.iss.
Function un.StoredValue
  StrCpy $1 ""
  ${If} ${RunningX64}
    SetRegView 64
    ReadRegStr $1 HKLM `SOFTWARE\${MyAppRegKey}` $0
    SetRegView 32
  ${EndIf}
  ${If} $1 == ""
    ReadRegStr $1 HKLM `SOFTWARE\${MyAppRegKey}` $0
  ${EndIf}
FunctionEnd

; The agent writes a random code at install and the server keeps it. Without
; it (/UNINSTALLCODE=<code> or ULRMM_UNINSTALL_CODE) the uninstall stops here.
; Once the service keeps the code encrypted, UninstallCodeSum is its SHA-256.
Function un.onInit
  !insertmacro ParseArgs "un."
  ; NSIS runs the uninstaller as a copy in %TEMP% with the directory the
  ; file was started from; only the fixed program directory is removed.
  Call un.SysDrive
  StrCpy $0 "UninstallCode"
  Call un.StoredValue
  StrCpy $7 $1
  ${If} $7 != ""
    ${un.GetParameters} $R0
    ClearErrors
    ${un.GetOptions} $R0 "/UNINSTALLCODE=" $8
    ${If} $8 == ""
      ReadEnvStr $8 ULRMM_UNINSTALL_CODE
    ${EndIf}
    StrCpy $0 "UninstallCodeSum"
    Call un.StoredValue
    StrCpy $9 $1
    StrCpy $R5 0
    ${If} $9 != ""
      ${If} $8 != ""
        StrCpy $0 $8
        Call un.Sha256Hex
        ; StrCmp ignores case, like CompareText in setup.iss
        ${If} $1 != ""
        ${AndIf} $1 == $9
          StrCpy $R5 1
        ${EndIf}
      ${EndIf}
    ${ElseIf} $8 S== $7
      StrCpy $R5 1
    ${EndIf}
    ${If} $R5 != 1
      !insertmacro Log "Uninstall refused: missing or wrong uninstall code"
      MessageBox MB_ICONSTOP "This agent is protected. Uninstall it from the dashboard, or run the uninstaller with /UNINSTALLCODE=<code>." /SD IDOK
      !insertmacro CloseLog
      SetErrorLevel 1
      Quit
    ${EndIf}
  ${EndIf}
FunctionEnd

Section "Uninstall"
  ; The self-heal task goes first: while the config is still there it would
  ; register a missing service again.
  !insertmacro Run `"$SYSDIR\schtasks.exe" /End /TN "${MyAppSvcName}-selfheal"` "end self-heal task"
  !insertmacro Run `"$SYSDIR\schtasks.exe" /Delete /TN "${MyAppSvcName}-selfheal" /F` "delete self-heal task"
  Sleep 1000 ; setup.iss pings for a second before net stop
  !insertmacro Run `"$SYSDIR\net.exe" stop "${MyAppSvcName}"` "Stop service"
  !insertmacro Run `"$SYSDIR\taskkill.exe" /F /IM "${MyAppExeName}"` "taskkill"
  !insertmacro Run `"$SYSDIR\sc.exe" delete "${MyAppSvcName}"` "delete service"

  SetOutPath "$SYSDIR"
  !insertmacro Run `"$INSTDIR\${MyAppExeName}" -m cleanup` "cleanup"
  !insertmacro Run `"$SYSDIR\taskkill.exe" /F /IM "${MyAppExeName}"` "taskkill"
  !insertmacro Run `"$INSTDIR\${MESHEXE}" -fulluninstall` "mesh uninstall"

  SetRegView 32
  DeleteRegKey HKLM "${UNINST_KEY}"
  StrCpy $0 $INSTDIR
  Call un.RemoveDir
  StrCpy $0 "$SysDrive\Program Files\Mesh Agent"
  Call un.RemoveDir
  !insertmacro CloseLog
SectionEnd
