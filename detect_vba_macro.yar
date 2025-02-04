rule Detect_Malicious_VBA_Macro
{
    meta:
        description = "Detects suspicious VBA macros that execute commands"
        author = "Pranith Jain"
        date = "2025-02-04"
        version = "1.0"
        
    strings:
        $vba_macro = "Sub AutoOpen"
        $vba_shell = "Shell("
        $vba_download = "URLDownloadToFileA"
        
    condition:
        $vba_macro and ($vba_shell or $vba_download)
}
