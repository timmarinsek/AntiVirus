rule Detect_Malicious_URLs_and_Signatures
{
    meta:
        description = "Pravilo za detekcijo zlonamernih URL-jev in znanih virusnih podpisov"
        author = "Tim Marinšek"
        version = "1.0"
        date = "2024-12-24"

    strings:
        $malicious_url = "http://malicious-url.com"
        $virus_signature1 = "malicious_payload"
        $virus_signature2 = { E8 ?? ?? ?? ?? 85 C0 74 0A }
    
    condition:
        any of ($malicious_url, $virus_signature1, $virus_signature2)
}

rule Detect_PE_Malware
{
    meta:
        description = "Pravilo za detekcijo zlonamernih izvršljivih datotek (PE)"
        author = "Tim Marinšek"
        version = "1.0"
        date = "2024-12-24"

    strings:
        $str1 = "suspicious_function"
        $str2 = { 60 89 E5 31 C0 }
        $str3 = "exploit_code"
    
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and 
        1 of ($str1, $str2, $str3)
}

rule Detect_Complex_Malware
{
    meta:
        description = "Napredno pravilo za detekcijo zlonamerne kode z binarnimi vzorci"
        author = "Tim Marinšek"
        version = "1.1"
        date = "2024-12-24"

    strings:
        $bin_pattern1 = { B8 ?? ?? ?? ?? FF D0 }
        $bin_pattern2 = { E9 ?? ?? ?? ?? 68 ?? ?? ?? ?? }
        $suspicious_string = "UnauthorizedAccessException"

    condition:
        all of ($bin_pattern1, $bin_pattern2) or $suspicious_string
}

rule Detect_Trojan_Behavior
{
    meta:
        description = "Pravilo za detekcijo trojanskih programov na podlagi sumljivega obnašanja"
        author = "Tim Marinšek"
        version = "1.0"
        date = "2024-12-24"

    strings:
        $cmd_string = "cmd.exe /c"
        $registry_key = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        $payload_execution = "powershell.exe -ExecutionPolicy Bypass"

    condition:
        all of ($cmd_string, $registry_key, $payload_execution)
}

rule Detect_Encrypted_Communication
{
    meta:
        description = "Pravilo za detekcijo datotek, ki uporabljajo sumljivo šifrirano komunikacijo"
        author = "Tim Marinšek"
        version = "1.0"
        date = "2024-12-24"

    strings:
        $rsa_key = { 30 82 ?? ?? 02 01 00 02 82 ?? ?? 00 }
        $aes_key = { 00 00 00 00 66 73 4C 4D 61 6C }
        $crypto_lib = "CryptoLib.dll"
    
    condition:
        1 of ($rsa_key, $aes_key) and $crypto_lib
}
