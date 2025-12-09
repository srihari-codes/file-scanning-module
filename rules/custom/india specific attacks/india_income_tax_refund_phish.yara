rule India_IncomeTax_Refund_Phish
{
    meta:
        description = "Phishing about Indian Income Tax refunds / ITR"
        author = "rakavi"
        severity = "high"

    strings:
        $it1 = "Income Tax Department" nocase
        $it2 = "incometaxindia" nocase
        $it3 = "e-Filing" nocase
        $itr = "ITR" ascii
        $refund = "tax refund" nocase
        $link = "Click here to get your refund" nocase

    condition:
        2 of ($it1,$it2,$it3,$itr) and
        $refund and
        $link
}
rule India_IncomeTax_Refund_Phish
{
    meta:
        description = "Phishing about Indian Income Tax refunds / ITR"
        author = "rakavi"
        severity = "high"

    strings:
        $it1 = "Income Tax Department" nocase
        $it2 = "incometaxindia" nocase
        $it3 = "e-Filing" nocase
        $itr = "ITR" ascii
        $refund = "tax refund" nocase
        $link = "Click here to get your refund" nocase

    condition:
        2 of ($it1,$it2,$it3,$itr) and
        $refund and
        $link
}
