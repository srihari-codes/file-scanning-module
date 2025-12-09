rule India_Telecom_SIM_Block_Threat
{
    meta:
        description = "Phishing/scam content claiming SIM will be blocked (Airtel/Jio/Vi/BSNL)"
        author = "rakavi"
        severity = "medium"

    strings:
        $airtel = "Airtel" nocase
        $jio    = "Jio" nocase
        $vi     = "Vi (Vodafone Idea)" nocase
        $bsnl   = "BSNL" nocase
        $kyc    = "KYC" nocase
        $block1 = "your SIM will be blocked" nocase
        $block2 = "SIM card will be deactivated" nocase

    condition:
        1 of ($airtel,$jio,$vi,$bsnl) and
        $kyc and
        1 of ($block1,$block2)
}
