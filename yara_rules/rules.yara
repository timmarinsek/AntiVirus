rule MaliciousExample
{
    strings:
        $malicious_string = "virus_signature"
    condition:
        $malicious_string
}
