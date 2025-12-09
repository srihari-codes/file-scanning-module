import "pe"
import "math"

rule ZeroDay_Heur_High_Entropy_Binary
{
    meta:
        description = "Generic PE with multiple extremely high-entropy sections (packed / obfuscated / 0-day carrier)"
        author = "rakavi"
        severity = "medium"

    condition:
        pe.is_pe and
        uint16(0) == 0x5A4D and
        pe.number_of_sections >= 3 and
        for any i in (0..pe.number_of_sections-1):
            (
                pe.sections[i].entropy > 7.4 and
                pe.sections[i].raw_data_size > 4096
            ) and
        filesize < 20MB
}
