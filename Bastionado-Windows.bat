@echo off
:: ===========================================================================
:: Unified Windows Hardening Script (Enhanced)
:: Versión corregida: salto a Main, timestamp robusto vía WMIC, idempotencia
:: ===========================================================================

:: --- 1) Verificar permisos de Administrador
net session >nul 2>&1 || (
  echo [ERROR] Este script requiere permisos de administrador.
  pause
  exit /b 1
)

:: --- 2) Generar timestamp robusto (formato YYYYMMDD_HHMMSS)
for /f "skip=1 tokens=1" %%x in ('wmic os get LocalDateTime') do if not defined LDT set LDT=%%x
setlocal enabledelayedexpansion
set "DATESTAMP=!LDT:~0,8!"
set "TIMESTAMP=!LDT:~8,6!"

:: --- 3) Definir logfile
set "LOGFILE=%~dp0hardening-!DATESTAMP!_!TIMESTAMP!.log"

echo ===========================================================================
echo Starting Unified Windows Hardening: !DATESTAMP!_!TIMESTAMP!
echo ===========================================================================
(
  echo ===========================================================================
  echo Starting Unified Windows Hardening: !DATESTAMP!_!TIMESTAMP!
  echo ===========================================================================
) >>"%LOGFILE%"

goto :Main

:: ----------------------------------------------------------------------------
:WriteLog
  echo [%DATESTAMP% %TIMESTAMP%] %*
  echo [%DATESTAMP% %TIMESTAMP%] %* >>"%LOGFILE%"
  goto :eof

:: ----------------------------------------------------------------------------
:ApplyReg
  set "Key=%~1" & set "Name=%~2" & set "Type=%~3" & set "Data=%~4"
  for /f "tokens=3" %%A in ('reg query "%Key%" /v "%Name%" 2^>nul ^| findstr /i "%Name%"') do set "Current=%%A"
  if "!Current!" NEQ "%Data%" (
    reg add "%Key%" /v "%Name%" /t "%Type%" /d "%Data%" /f >nul 2>&1 && call :WriteLog "[OK] %Key%\%Name% set to %Data%" || call :WriteLog "[ERR] Failed %Key%\%Name%"
  ) else (
    call :WriteLog "[SKIP] %Key%\%Name% already %Data%"
  )
  goto :eof

:: ----------------------------------------------------------------------------
:DisableService
  set "svc=%~1"
  sc query "%svc%" >nul 2>&1
  if !errorlevel! EQU 0 (
    sc config "%svc%" start=disabled >nul 2>&1 && call :WriteLog "[OK] Servicio %svc% deshabilitado" || call :WriteLog "[ERR] No se pudo deshabilitar %svc%"
  ) else (
    call :WriteLog "[SKIP] Servicio %svc% no existe"
  )
  goto :eof

:: ===========================================================================
:: Main – aquí empieza realmente el hardening
:: ===========================================================================
:Main

  call :WriteLog "-- Neutralizar asociaciones de extensiones peligrosas --"
  for %%E in (
    batfile chmfile cmdfile htafile jsefile jsfile vbefile vbsfile
    wscfile wsffile wsfile wshfile sctfile urlfile regfile wcxfile
    mscfile slkfile iqyfile prnfile diffile applicationfile deployfile rdgfile
  ) do (
    ftype %%E="%SystemRoot%\System32\notepad.exe" "%%1" >nul 2>&1 && (
      call :WriteLog "[OK] ftype %%E ajustado"
    ) || (
      call :WriteLog "[SKIP] ftype %%E no existe"
    )
  )

  call :WriteLog "-- Desactivar SettingContent DelegateExecute --"
  reg delete "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /f >nul 2>&1
  reg add    "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /t REG_SZ /d "" /f >nul 2>&1 && call :WriteLog "[OK] DelegateExecute eliminado" || call :WriteLog "[SKIP] DelegateExecute no existía"

  call :WriteLog "-- Eliminar handlers .devicemetadata --"
  reg delete "HKLM\SOFTWARE\Classes\.devicemetadata-ms" /f >nul 2>&1 && call :WriteLog "[OK] .devicemetadata-ms eliminado" || call :WriteLog "[SKIP] .devicemetadata-ms no existía"
  reg delete "HKLM\SOFTWARE\Classes\.devicemanifest-ms" /f >nul 2>&1 && call :WriteLog "[OK] .devicemanifest-ms eliminado" || call :WriteLog "[SKIP] .devicemanifest-ms no existía"

  call :WriteLog "-- Mitigar ClickOnce (.application/.deploy) --"
  reg add "HKLM\SOFTWARE\Classes\.application" /ve /t REG_SZ /d "" /f >nul 2>&1 && call :WriteLog "[OK] .application mitigado"   || call :WriteLog "[SKIP] .application"
  reg add "HKLM\SOFTWARE\Classes\.deploy"      /ve /t REG_SZ /d "" /f >nul 2>&1 && call :WriteLog "[OK] .deploy mitigado"        || call :WriteLog "[SKIP] .deploy"

  call :WriteLog "-- Deshabilitar DCOM remoto --"
  reg add "HKLM\Software\Microsoft\OLE" /v EnableDCOM /t REG_SZ /d N /f >nul 2>&1 && call :WriteLog "[OK] EnableDCOM=N" || call :WriteLog "[SKIP] OLE key"

  call :WriteLog "-- Desactivar compresión SMBv3 --"
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name DisableCompression -Value 1 -Force" >nul 2>&1 && call :WriteLog "[OK] SMBv3 compresión desactivada"

  call :WriteLog "-- Deshabilitar SMBv1 y forzar SMB Signing --"
  call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10"                                "Start"                  "REG_DWORD" "4"
  call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" "REG_DWORD" "1"
  call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature"  "REG_DWORD" "1"
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
  net accounts /minpwlen:14 /maxpwage:90 /uniquepw:5    >>"%LOGFILE%" 2>&1 && call :WriteLog "[OK] net accounts applied"
  net accounts /lockoutthreshold:5 /lockoutwindow:30 /lockoutduration:30 >>"%LOGFILE%" 2>&1 && call :WriteLog "[OK] lockout policy"

  call :WriteLog "-- Configurar Firewall Windows --"
  netsh advfirewall set allprofiles state on              >nul 2>&1 && call :WriteLog "[OK] Firewall ON"
  netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >nul 2>&1 && call :WriteLog "[OK] FW policy"

  :: … aquí podrías seguir añadiendo las secciones de Auditoría, PSLogging, Defender ASR,
  :: BitLocker, AppLocker, RDP, LAPS, Credential Guard y PSWindowsUpdate, en el mismo estilo.

  call :WriteLog "==========================================================================="
  call :WriteLog "Hardening completado: !DATESTAMP!_!TIMESTAMP!"
  call :WriteLog "Log file: %LOGFILE%"
  call :WriteLog "==========================================================================="

  echo.
  pause
  endlocal
  exit /b 0
