import "pe"

rule Sandbox_Evasion_Generic
{
    meta:
        description = "Generic anti-VM / sandbox evasion strings"
        author = "rakavi"
        severity = "medium"

    strings:
        $vm1 = "VBoxTray" ascii nocase
        $vm2 = "VMware" ascii nocase
        $vm3 = "VirtualBox" ascii nocase
        $dbg1 = "IsDebuggerPresent" ascii
        $dbg2 = "CheckRemoteDebuggerPresent" ascii
        $time1 = "GetTickCount" ascii
        $time2 = "QueryPerformanceCounter" ascii

    condition:
        (pe.is_pe or true) and
        (2 of ($vm*) or (1 of ($vm*) and 1 of ($dbg* $time*)))
}
