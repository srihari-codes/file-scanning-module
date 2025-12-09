import "pe"

rule Suspicious_API_Combo
{
    meta:
        description = "Suspicious combination of process injection APIs"
        author = "rakavi"
        severity = "high"

    strings:
        $a1 = "VirtualAllocEx" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $a4 = "OpenProcess" ascii wide

    condition:
        pe.is_pe and
        uint16(0) == 0x5A4D and
        2 of ($a*)
}
