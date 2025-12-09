rule India_UPI_Phishing_Doc
{
    meta:
        description = "Office doc phishing around UPI/KYC (India BFSI)"
        author = "rakavi"
        severity = "high"

    strings:
        $upi1 = "Unified Payments Interface" nocase
        $upi2 = "UPI ID" nocase
        $bhim = "BHIM UPI" nocase
        $kyc1 = "update your KYC" nocase
        $kyc2 = "KYC will be blocked" nocase
        $txt1 = "NPCI" nocase
        $bank1 = "SBI" ascii nocase
        $bank2 = "HDFC Bank" ascii nocase
        $bank3 = "ICICI Bank" ascii nocase
        $bank4 = "Axis Bank" ascii nocase

    condition:
        (uint16(0) == 0xD0CF or uint32(0) == 0x504B0304) and
        ( (1 of ($upi*)) and (1 of ($kyc*)) and (1 of ($bank*)) )
}
