rule Persistence_Registry_Script
{
    meta:
        description = "Script containing registry persistence (Run/RunOnce)"
        author = "rakavi"
        severity = "medium"

    strings:
        $reg1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg3 = "RunOnce" nocase
        $cmd = "cmd.exe" nocase
        $ps = "powershell.exe" nocase

    condition:
        1 of ($reg*) and ( $cmd or $ps )
}
