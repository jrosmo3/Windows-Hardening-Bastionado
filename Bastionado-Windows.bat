@echo off
:: ===========================================================================
:: Unified Windows Hardening Script (Enhanced)
:: Basado en gist original y mejores prácticas: modular, logging, idempotente
:: Controles STIG/CIS, mitigaciones, Defender ASR, LAPS, Credential Guard,
:: PS logging, remediación de parches, AppLocker y más.
:: ===========================================================================

:: Verificar privilegios de administrador
net session >nul 2>&1 || (
  echo [ERROR] Este script requiere permisos de administrador.
  pause
  exit /b 1
)

setlocal enabledelayedexpansion
set "LOGFILE=%~dp0hardening-%date:~10,4%-%date:~4,2%-%date:~7,2%_%time:~0,2%-%time:~3,2%-%time:~6,2%.log"
(
  echo ===========================================================================
  echo Starting Unified Windows Hardening: %date% %time%
  echo ===========================================================================
) >> "%LOGFILE%"

:: Funciones
:WriteLog
  echo [%date% %time%] %* >> "%LOGFILE%"
  goto :eof

:ApplyReg
  set "Key=%~1" & set "Name=%~2" & set "Type=%~3" & set "Data=%~4"
  for /f "tokens=3" %%A in ('reg query "%Key%" /v "%Name%" 2^>nul ^| findstr /i "%Name%"') do set "Current=%%A"
  if "!Current!" NEQ "%Data%" (
    reg add "%Key%" /v "%Name%" /t "%Type%" /d "%Data%" /f >> "%LOGFILE%" 2>&1 && call :WriteLog "[OK] %Key%\\%Name% set to %Data%" || call :WriteLog "[ERR] Failed %Key%\\%Name%"
  ) else (
    call :WriteLog "[SKIP] %Key%\\%Name% already %Data%"
  )
  goto :eof

:DisableService
  set "svc=%~1"
  sc query "%svc%" >nul 2>&1
  if !errorlevel! EQU 0 (
    sc config "%svc%" start=disabled >> "%LOGFILE%" 2>&1 && call :WriteLog "[OK] Servicio %svc% deshabilitado" || call :WriteLog "[ERR] No se pudo deshabilitar %svc%"
  ) else call :WriteLog "[SKIP] Servicio %svc% no existe"
  goto :eof

:: ---------------------------------------------------------------------------
:: Sección I: Mitigaciones básicas y originales
:: ---------------------------------------------------------------------------
call :WriteLog "-- Neutralizar asociaciones de extensiones peligrosas --"
for %%E in (batfile chmfile cmdfile htafile jsefile jsfile vbefile vbsfile wscfile wsffile wsfile wshfile sctfile urlfile regfile wcxfile mscfile slkfile iqyfile prnfile diffile applicationfile deployfile rdgfile) do (
  ftype %%E="%%SystemRoot%%\System32\notepad.exe" "%%1" >> "%LOGFILE%" 2>&1
  call :WriteLog "[OK] ftype %%E ajustado"
)

call :WriteLog "-- Desactivar SettingContent DelegateExecute --"
reg delete "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /f >> "%LOGFILE%" 2>&1
reg add "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /t REG_SZ /d "" /f >> "%LOGFILE%" 2>&1 && call :WriteLog "[OK] DelegateExecute eliminado"

call :WriteLog "-- Eliminar handlers .devicemetadata--"
reg delete "HKLM\SOFTWARE\Classes\.devicemetadata-ms" /f >> "%LOGFILE%" 2>&1
reg delete "HKLM\SOFTWARE\Classes\.devicemanifest-ms" /f >> "%LOGFILE%" 2>&1

call :WriteLog "-- Mitigar ClickOnce (.application/.deploy) --"
reg add "HKLM\SOFTWARE\Classes\.application" /ve /t REG_SZ /d "" /f >> "%LOGFILE%" 2>&1
reg add "HKLM\SOFTWARE\Classes\.deploy" /ve /t REG_SZ /d "" /f >> "%LOGFILE%" 2>&1

call :WriteLog "-- Mitigación Airstrike Wireless --"
call :ApplyReg "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI" "REG_DWORD" "1"

call :WriteLog "-- Deshabilitar DCOM remoto --"
reg add "HKLM\Software\Microsoft\OLE" /v EnableDCOM /t REG_SZ /d N /f >> "%LOGFILE%" 2>&1

call :WriteLog "-- Desactivar compresión SMBv3 --"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name DisableCompression -Value 1 -Force" >> "%LOGFILE%" 2>&1

:: ---------------------------------------------------------------------------
:: Sección II: Hardening avanzado
:: ---------------------------------------------------------------------------
call :WriteLog "-- Deshabilitar SMBv1 y forzar SMB Signing --"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" "REG_DWORD" "4"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" "REG_DWORD" "1"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature" "REG_DWORD" "1"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" "REG_DWORD" "1"

call :WriteLog "-- Endurecer TLS/SSL --"
for %%P in ("SSL 2.0" "SSL 3.0" "TLS 1.0" "TLS 1.1") do (
  call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\%%~P\Client" "Enabled" "REG_DWORD" "0"
  call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\%%~P\Server" "Enabled" "REG_DWORD" "0"
)
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" "Enabled" "REG_DWORD" "1"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" "Enabled" "REG_DWORD" "1"

call :WriteLog "-- Deshabilitar servicios innecesarios --"
for %%S in (Fax XblGameSave XboxGipSvc WSearch RemoteRegistry Telnet Spooler) do call :DisableService "%%S"

call :WriteLog "-- Políticas de contraseña y bloqueo --"
net accounts /minpwlen:14 /maxpwage:90 /uniquepw:5 >> "%LOGFILE%" 2>&1
net accounts /lockoutthreshold:5 /lockoutwindow:30 /lockoutduration:30 >> "%LOGFILE%" 2>&1

call :WriteLog "-- Configurar Firewall Windows --"
netsh advfirewall set allprofiles state on >> "%LOGFILE%" 2>&1
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >> "%LOGFILE%" 2>&1

call :WriteLog "-- Deshabilitar LLMNR --"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableMulticast" "REG_DWORD" "0"

call :WriteLog "-- Reforzar UAC --"
call :ApplyReg "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" "REG_DWORD" "1"
call :ApplyReg "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" "REG_DWORD" "2"

call :WriteLog "-- Deshabilitar WDigest y forzar LMv2 --"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" "REG_DWORD" "0"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" "REG_DWORD" "5"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "restrictanonymous" "REG_DWORD" "1"

call :WriteLog "-- Configurar políticas de auditoría --"
for %%C in ("Account Logon" "Account Management" "Logon/Logoff" "Policy Change" "Privilege Use" "System" "Object Access") do auditpol /set /category:"%%~C" /success:enable /failure:enable >> "%LOGFILE%" 2>&1

call :WriteLog "-- Tamaño y retención de Event Logs --"
for %%L in (Application Security System) do wevtutil sl %%L /ms:2097152 /rt:false >> "%LOGFILE%" 2>&1

call :WriteLog "-- Logging avanzado de PowerShell --"
call :ApplyReg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" "REG_DWORD" "1"
call :ApplyReg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" "REG_DWORD" "1"
call :ApplyReg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" "REG_DWORD" "1"
call :ApplyReg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "OutputDirectory" "REG_SZ" "%SystemRoot%\Temp\PS-Transcripts"

call :WriteLog "-- Microsoft Defender Antivirus & ASR rules --"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $false -PUAProtection Enable -EnableNetworkProtection Enabled -MAPSReporting Advanced; Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A,75668C1F-73B5-4CF0-9AD6-98CBB30098AE -AttackSurfaceReductionRules_Actions Enabled; Set-MpPreference -EnableControlledFolderAccess Enabled" >> "%LOGFILE%" 2>&1

call :WriteLog "-- Encriptar disco con BitLocker --"
manage-bde -status C: | findstr /i "Percentage Encrypted.*100%" >nul || ( manage-bde -on C: -RecoveryPassword >> "%LOGFILE%" 2>&1 && call :WriteLog "[OK] BitLocker iniciado" )

call :WriteLog "-- Reglas predeterminadas AppLocker --"
powershell -NoProfile -ExecutionPolicy Bypass -Command "New-AppLockerPolicy -Default -XML > '%~dp0AppLockerPolicy.xml'; Set-AppLockerPolicy -XMLPolicy ('%~dp0AppLockerPolicy.xml') -Merge" >> "%LOGFILE%" 2>&1

call :WriteLog "-- Deshabilitar RDP si no es necesario --"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" "REG_DWORD" "1"
sc config TermService start=disabled >> "%LOGFILE%" 2>&1

call :WriteLog "-- Instalar y configurar LAPS --"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force; Install-Module LAPS -Force; Import-Module LAPS; Set-AdmPwdPasswordSettings -AllowedLength 14 -PasswordComplexity 4 -PasswordAgeDays 30" >> "%LOGFILE%" 2>&1

call :WriteLog "-- Habilitar Credential Guard --"
bcdedit /set hypervisorlaunchtype auto >> "%LOGFILE%" 2>&1 && call :WriteLog "[OK] hypervisorlaunchtype=auto"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity" "REG_DWORD" "1"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "RequirePlatformSecurityFeatures" "REG_DWORD" "1"

call :WriteLog "-- Remediar parches via PSWindowsUpdate --"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Install-Module PSWindowsUpdate -Force -Confirm:$false; Import-Module PSWindowsUpdate; Get-WindowsUpdate -AcceptAll; Install-WindowsUpdate -AcceptAll -AutoReboot" >> "%LOGFILE%" 2>&1

:: ---------------------------------------------------------------------------
:: Finalización
:: ---------------------------------------------------------------------------
(
  echo ===========================================================================
  echo Hardening completado: %date% %time%
  echo Log file: %LOGFILE%
  echo ===========================================================================
) >> "%LOGFILE%"
endlocal
exit /b 0
