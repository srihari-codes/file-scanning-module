rule PowerShell_Obfuscated_Command
{
    meta:
        description = "Obfuscated PowerShell command patterns in any file"
        author = "rakavi"
        severity = "high"

    strings:
        $ps1 = "powershell.exe" ascii nocase
        $ps2 = "PowerShell" ascii nocase
        $enc = "-enc" ascii nocase
        $b64 = "FromBase64String" ascii nocase
        $iex = "IEX(" ascii nocase
        $hidden = "-WindowStyle hidden" ascii nocase

    condition:
        1 of ($ps*) and
        ( $enc or $b64 or $iex or $hidden )
}
