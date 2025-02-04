rule Detect_RAT_Tools
{
    meta:
        description = "Detects Remote Access Tools (RATs)"
        author = "Pranith Jain"
        date = "2025-02-04"
        version = "1.0"
        
    strings:
        $rat_1 = "msfvenom"
        $rat_2 = "njRAT"
        $rat_3 = "RemoteAccess"
        $rat_4 = "RAT.exe"
        
    condition:
        any of them
}
