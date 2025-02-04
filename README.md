YARA & Sigma Detection Rules

A set of detection rules for use in Security Operations Centers (SOC) to monitor and detect potential threats in the environment. These rules are designed to identify various types of security incidents using YARA and Sigma formats.

Rules:

1️⃣ YARA Rule: Detect Malicious PowerShell Scripts
File: [detect_powershell_malware.yar]

Description: A YARA rule designed to detect malicious PowerShell scripts. This rule scans for suspicious PowerShell activity often associated with malware and other malicious actions.

2️⃣ Sigma Rule: Brute Force Attack Detection

File: [brute_force_sigma.yml]

Description: A Sigma rule created to detect brute force attack attempts by monitoring system logs for patterns indicative of repeated failed login attempts.
