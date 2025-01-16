with open("test_complex_malwaree.bin", "wb") as f:

    f.write(b"\xB8\x12\x34\x56\x78\xFF\xD0")  


    f.write(b"\xE9\x90\x12\x34\x56\x68\xAB\xCD\xEF\x00")  


    f.write(b"UnauthorizedAccessException")

    f.write(b"\x00" * 1024)
    f.write(b"End of test file.")
