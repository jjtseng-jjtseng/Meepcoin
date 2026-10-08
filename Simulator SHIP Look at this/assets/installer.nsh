; Extra per-user entry point. Both shortcuts use the same executable and data.
!macro customInstall
  CreateShortCut "$DESKTOP\MeepCoin Local Lab (Browser).lnk" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" "--browser" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" 0
  CreateShortCut "$SMPROGRAMS\MeepCoin Local Lab (Browser).lnk" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" "--browser" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" 0
!macroend

!macro customUnInstall
  Delete "$DESKTOP\MeepCoin Local Lab (Browser).lnk"
  Delete "$SMPROGRAMS\MeepCoin Local Lab (Browser).lnk"
!macroend
