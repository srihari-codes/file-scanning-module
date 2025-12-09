rule India_GOV_NIC_Lure_Doc
{
    meta:
        description = "Office doc impersonating Indian govt (.gov.in / .nic.in)"
        author = "rakavi"
        severity = "high"

    strings:
        $hdr_hi = "Government of India" nocase
        $hdr2 = "Ministry of" nocase
        $nic = ".nic.in" nocase
        $gov = ".gov.in" nocase
        $seal = "भारत सरकार" wide nocase
        $conf = "Strictly Confidential" nocase

    condition:
        (uint16(0) == 0xD0CF or uint32(0) == 0x504B0304) and
        (1 of ($gov,$nic)) and
        (1 of ($hdr_hi,$hdr2,$seal)) and
        $conf
}
