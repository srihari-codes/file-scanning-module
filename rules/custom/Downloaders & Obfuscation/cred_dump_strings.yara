rule Credential_Dumping_Strings
{
    meta:
        description = "Common credential dumping tool strings (generic, possible 0-day variants)"
        author = "rakavi"
        severity = "high"

    strings:
        $mimikatz1 = "mimikatz" ascii nocase
        $sekurlsa = "sekurlsa::logonpasswords" ascii nocase
        $wdigest = "wdigest" ascii nocase
        $lsass = "lsass.exe" ascii nocase
        $dmp = ".dmp" ascii nocase

    condition:
        2 of ($mimikatz1, $sekurlsa, $wdigest, $lsass, $dmp)
}
