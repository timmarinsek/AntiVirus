with open("test_trojan_behavior.txt", "w") as f:

    f.write("cmd.exe /c\n")


    f.write("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n")

    f.write("powershell.exe -ExecutionPolicy Bypass\n")

    f.write("This is a test file to simulate trojan-like behavior.\n")
    f.write("End of test data.")
