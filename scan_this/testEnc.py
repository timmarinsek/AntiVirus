with open("test_encrypted_communication.bin", "wb") as f:
    
    f.write(bytes.fromhex("30 82 00 00 02 01 00 02 82 00 00"))

    f.write(bytes.fromhex("00 00 00 00 66 73 4C 4D 61 6C"))

    f.write(b"CryptoLib.dll")


    f.write(b"\x00" * 1024)
    f.write(b"End of test file.")
