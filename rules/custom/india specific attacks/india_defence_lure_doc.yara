rule India_Defence_Lure_Doc
{
    meta:
        description = "Lure documents themed around Indian Army / defence"
        author = "rakavi"
        severity = "high"

    strings:
        $lure1 = "Revision of Officers posting policy" nocase
        $army1 = "Indian Army" nocase
        $army2 = "HQ IDS" nocase
        $army3 = "Directorate of Military Intelligence" nocase
        $email = "@army.mil.in" nocase
        $class = "CLASSIFIED" nocase

    condition:
        (uint16(0) == 0xD0CF or uint32(0) == 0x504B0304) and
        (1 of ($lure1,$army1,$army2,$army3,$email)) and
        $class
}
