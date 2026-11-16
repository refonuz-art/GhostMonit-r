; Ghost Monitor uninstaller hook: remove the hidden ransomware decoy files we planted.
!macro NSIS_HOOK_PREUNINSTALL
  ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --cleanup'
!macroend
