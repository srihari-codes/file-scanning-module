rule India_Aadhaar_PAN_Phish
{
    meta:
        description = "Phishing content targeting Aadhaar / PAN / e-KYC"
        author = "rakavi"
        severity = "medium"

    strings:
        $aadhaar1 = "Aadhaar" nocase
        $aadhaar2 = "uidai.gov.in" nocase
        $pan1 = "PAN Card" nocase
        $pan2 = "NSDL e-Gov" nocase
        $kyc = "e-KYC" nocase
        $block = "your Aadhaar will be deactivated" nocase
        $update = "update your Aadhaar details" nocase

    condition:
        2 of ($aadhaar* $pan* $kyc) and
        1 of ($block,$update)
}
