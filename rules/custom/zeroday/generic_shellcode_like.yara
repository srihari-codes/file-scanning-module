rule Generic_Shellcode_Like
{
    meta:
        description = "Generic x86 shellcode-like pattern in any file"
        author = "rakavi"
        severity = "medium"

    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        $get_eip1 = { E8 00 00 00 00 5B }  // call + pop ebx
        $get_eip2 = { E8 00 00 00 00 58 }  // call + pop eax

    condition:
        filesize < 2MB and
        ( $nop_sled or (1 of ($get_eip*)) )
}
