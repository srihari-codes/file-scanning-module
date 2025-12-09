rule Base64_Heavy_Suspicious
{
    meta:
        description = "Large embedded Base64 blob with suspicious keywords nearby"
        author = "rakavi"
        severity = "medium"

    strings:
        $b64blob = /[A-Za-z0-9+\/]{200,}={0,2}/
        $ps = "powershell" nocase
        $exe = ".exe" nocase
        $download = "DownloadString" nocase
        $invoke = "Invoke-" nocase

    condition:
        $b64blob and 1 of ($ps, $exe, $download, $invoke)
}
