import "pe"

rule Packed_PE_Suspicious
{
    meta:
        description = "Heuristic for packed or obfuscated PE (possible zero day)"
        author = "rakavi"
        date = "2025-12-09"
        severity = "high"

    condition:
        pe.is_pe and
        uint16(0) == 0x5A4D and
        pe.number_of_sections > 3 and
        for any i in (0..pe.number_of_sections - 1):
            (
                pe.sections[i].entropy > 7.3 and
                pe.sections[i].raw_data_size > 10240
            )
}
