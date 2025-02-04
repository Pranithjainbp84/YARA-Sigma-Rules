# YARA & Sigma Detection Rules

This repository contains a set of **YARA** and **Sigma** detection rules designed for use in **Security Operations Centers (SOC)** to monitor and detect potential threats in your environment. The rules are written to identify various types of security incidents such as malicious scripts, brute-force attacks, and remote access tools.

## Contents:

### 1. **YARA Rules**:

- **Malicious PowerShell Script Detection**  
  [detect_powershell_malware.yar]  
  This rule detects PowerShell commands typically associated with malware.

- **Suspicious PowerShell EncodedCommand**  
  [detect_powershell_encodedcommand.yar]  
  Identifies PowerShell usage with the `-EncodedCommand` option, often used in obfuscated attack scenarios.

- **Malicious VBA Macro Detection**  
  [detect_vba_macro.yar]  
  Detects suspicious VBA macros that execute commands or download files.

- **Remote Access Tools (RAT) Detection**  
  [detect_rat.yar]  
  Identifies known RAT tools like `msfvenom` and `njRAT`.

### 2. **Sigma Rule**:

- **Brute Force Attack Detection**  
  [brute_force_sigma.yml]  
  Monitors Windows Security logs (EventID 4625) to detect multiple failed login attempts indicative of brute-force attacks.




