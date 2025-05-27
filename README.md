# Windows-Hardening-Bastionado
Script para bastionar Windows
Este repositorio contiene un script de hardening unificado para Windows 10/Server, que aplica múltiples controles de seguridad de forma automatizada e idempotente:

- Mitigaciones originales (ClickOnce, Airstrike, DCOM, asociaciones de archivos peligrosos)  
- Controles STIG/CIS: SMBv1/v3, TLS/SSL, servicios, UAC, LLMNR, WDigest/LMv2  
- Políticas de auditoría y Event Logs  
- Logging avanzado de PowerShell (ScriptBlock y Module Logging, Transcripción)  
- Microsoft Defender Antivirus con reglas ASR y Controlled Folder Access  
- BitLocker en disco del sistema  
- Reglas predeterminadas de AppLocker  
- Deshabilitación de RDP  
- LAPS (Local Admin Password Solution)  
- Credential Guard  
- Remediación de parches con PSWindowsUpdate  

## Requisitos

- Windows 10 / Windows Server 2016+  
- Ejecutar como administrador  
- Conectividad a Internet para descargar módulos de PowerShell  

## Uso

1. Clona o descarga este repositorio.  
2. Coloca el archivo `unified-windows-hardening-enhanced.cmd` en una ruta accesible.  
3. Abre PowerShell/CMD como administrador.  
4. Ejecuta:
   ```powershell
   .\script.cmd
