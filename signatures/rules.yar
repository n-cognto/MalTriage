
rule example_malware {
    meta:
        description = "Example YARA rule for demonstration"
        author = "maltriage"
        severity = "high"
    strings:
        $s1 = "This is an example malicious string" nocase
        $s2 = "virus" nocase
        $s3 = "malware" nocase
        $hex1 = { 4D 5A 90 00 03 00 00 00 } // Example MZ header pattern
    condition:
        uint16(0) == 0x5A4D and // MZ header check
        ($s1 or (2 of ($s2, $s3, $hex1)))
}
    