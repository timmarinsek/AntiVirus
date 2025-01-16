with open("test_pe_malware.exe", "wb") as f:
    f.write(b"MZ")  
    f.write(b"\x00" * 58)  

    f.write(b"suspicious_function")

    f.write(b"\x60\x89\xE5\x31\xC0")

    f.write(b"This is a test file for YARA PE malware detection.\n")
    f.write(b"exploit_code")