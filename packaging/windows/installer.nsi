Unicode true

!include "MUI2.nsh"

!ifndef APP_NAME
!error "APP_NAME must be defined"
!endif

!ifndef APP_ID
!error "APP_ID must be defined"
!endif

!ifndef PRIMARY_EXE
!error "PRIMARY_EXE must be defined"
!endif

!ifndef STAGE_DIR
!error "STAGE_DIR must be defined"
!endif

!ifndef OUTPUT_EXE
!error "OUTPUT_EXE must be defined"
!endif

!ifndef ICON_PATH
!error "ICON_PATH must be defined"
!endif

Name "${APP_NAME}"
OutFile "${OUTPUT_EXE}"
InstallDir "$PROGRAMFILES\${APP_NAME}"
RequestExecutionLevel admin

!define MUI_ICON "${ICON_PATH}"
!define MUI_UNICON "${ICON_PATH}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install"
    SetOutPath "$INSTDIR"
    File /r "${STAGE_DIR}\*"

    WriteUninstaller "$INSTDIR\Uninstall.exe"

    CreateDirectory "$SMPROGRAMS\${APP_NAME}"
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${PRIMARY_EXE}"
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
    CreateShortcut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${PRIMARY_EXE}"

    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_ID}" "DisplayName" "${APP_NAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_ID}" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_ID}" "DisplayIcon" "$INSTDIR\${PRIMARY_EXE}"
SectionEnd

Section "Uninstall"
    Delete "$DESKTOP\${APP_NAME}.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk"
    RMDir "$SMPROGRAMS\${APP_NAME}"

    Delete "$INSTDIR\Uninstall.exe"
    RMDir /r "$INSTDIR"

    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_ID}"
SectionEnd
