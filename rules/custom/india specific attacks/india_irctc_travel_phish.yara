rule India_IRCTC_Travel_Phish
{
    meta:
        description = "Phishing themed around IRCTC / Indian Railways tickets"
        author = "rakavi"
        severity = "medium"

    strings:
        $irctc = "IRCTC" nocase
        $rail1 = "indianrail.gov.in" nocase
        $pnr = "PNR Status" nocase
        $etkt = "e-Ticket" nocase
        $refund = "Ticket Cancellation Refund" nocase
        $login = "IRCTC Next Generation eTicketing System" nocase

    condition:
        2 of ($irctc,$rail1,$pnr,$etkt,$login) and
        $refund
}
