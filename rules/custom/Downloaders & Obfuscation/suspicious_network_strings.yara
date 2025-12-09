rule Suspicious_Network_Strings
{
    meta:
        description = "Generic C2/networking patterns for unknown malware"
        author = "rakavi"
        severity = "medium"

    strings:
        $http = "http://" ascii nocase
        $https = "https://" ascii nocase
        $dns1 = ".onion" ascii nocase
        $ua1 = "User-Agent:" ascii nocase
        $post = "POST /" ascii nocase
        $get = "GET /" ascii nocase
        $php = ".php" ascii nocase
        $asp = ".asp" ascii nocase

    condition:
        (1 of ($http, $https)) and
        (1 of ($ua1, $post, $get)) and
        (1 of ($dns1, $php, $asp))
}

