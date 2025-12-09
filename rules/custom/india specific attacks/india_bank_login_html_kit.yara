rule India_Bank_Login_HTML_Kit
{
    meta:
        description = "HTML phishing kit imitating Indian bank logins"
        author = "rakavi"
        severity = "high"

    strings:
        $html = "<html" ascii nocase
        $sbi  = "onlinesbi.com" ascii nocase
        $hdfc = "netbanking.hdfcbank.com" ascii nocase
        $icici = "icicibank.com" ascii nocase
        $axis = "axisbank.com" ascii nocase
        $login = "Enter your OTP" nocase
        $pin = "ATM PIN" nocase
        $cvv = "CVV" nocase

    condition:
        $html at 0 and
        1 of ($sbi,$hdfc,$icici,$axis) and
        1 of ($login,$pin,$cvv)
}
