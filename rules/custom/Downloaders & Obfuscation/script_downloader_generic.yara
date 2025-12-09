rule Script_Downloader_Generic
{
    meta:
        description = "Generic downloader script (wscript/cscript + URL)"
        author = "rakavi"
        severity = "high"

    strings:
        $wscript = "WScript.Shell" ascii nocase
        $cscript = "cscript.exe" ascii nocase
        $url1 = "http://" ascii nocase
        $url2 = "https://" ascii nocase
        $download1 = "XMLHTTP" ascii nocase
        $download2 = "ADODB.Stream" ascii nocase
        $save = "SaveToFile" ascii nocase

    condition:
        filesize < 2MB and
        1 of ($wscript, $cscript) and
        1 of ($url*) and
        (1 of ($download*) or $save)
}

