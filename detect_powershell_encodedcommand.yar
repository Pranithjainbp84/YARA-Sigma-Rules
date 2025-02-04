rule Detect_Powershell_EncodedCommand
{
    meta:
        description = "Detects PowerShell command execution using -EncodedCommand"
        author = "Pranith Jain"
        date = "2025-02-04"
        version = "1.0"
        
    strings:
        $encoded_command = "-EncodedCommand"
        $powershell = "powershell.exe"
        
    condition:
        $powershell and $encoded_command
}
