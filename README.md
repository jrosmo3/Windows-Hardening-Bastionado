# Unified Windows Hardening Script (Enhanced)

Este repositorio contiene un script por lotes (`.bat`) para aplicar un conjunto de medidas de seguridad y endurecimiento (“hardening”) en sistemas Windows NT modernos (Windows 7/Server 2008 R2 en adelante), optimizado para Windows 10/11 y Windows Server 2016/2019.

---

## 📋 Índice

- [Características](#-características)  
- [Requisitos](#-requisitos)  
- [Instalación y Ejecución](#-instalación-y-ejecución)  
- [Cómo Funciona](#-cómo-funciona)  
- [Registro (Logging)](#-registro-logging)  
- [Personalización](#-personalización)  
- [Contribuir](#-contribuir)  
- [Licencia](#-licencia)

---

## 🔒 Características

- **Idempotente**: no aplica cambios redundantes  
- **Timestamp robusto**: genera logs con fecha/hora via WMIC (formato `YYYYMMDD_HHMMSS`)  
- **Logging completo**: registra cada paso en un fichero `hardening-<timestamp>.log`  
- **Modular**: separación en funciones para registro, aplicación de claves de registro y deshabilitación de servicios  
- **Medidas básicas**:  
  - Neutraliza asociaciones de extensiones peligrosas  
  - Mitiga ClickOnce y .devicemetadata handlers  
  - Deshabilita DCOM remoto  
  - Desactiva compresión SMBv3  
- **Hardening avanzado**:  
  - Deshabilita SMBv1 y fuerza SMB Signing  
  - Endurece protocolos TLS/SSL (sólo TLS 1.2)  
  - Deshabilita servicios innecesarios (Fax, WSearch, RemoteRegistry, etc.)  
  - Refuerza políticas de contraseña y bloqueo de cuentas  
  - Habilita y configura Windows Firewall  
- **Plantilla para ampliar**: sección marcada para añadir auditoría, PowerShell logging, ASR/Defender, BitLocker, AppLocker, RDP, LAPS, Credential Guard, Windows Update, etc.

---

## ⚙️ Requisitos

- Windows 7 (o superior) / Windows Server 2008 R2 (o superior)  
- Ejecutar como **Administrador**  
- **WMIC** (instalado por defecto en ediciones Pro/Server)  
- **PowerShell** (v3+ para llamadas a `Set-ItemProperty` y ASR)

---

## 🚀 Instalación y Ejecución

1. Clona este repositorio o descarga el script directamente:
   ```bat
   git clone https://github.com/TU_USUARIO/Windows-Hardening-Script.git
   cd Windows-Hardening-Script
