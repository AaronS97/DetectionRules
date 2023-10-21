rule njRAT {
    meta: 
        Author = "Aaron S." 
        Date_Created = "7 Oct 2022"
        Version = "1.0"
        Description = "Simple rule for detecting njRAT (Bladabindi) malware"

    strings:
        $string1 = "Exsample.exe"
        $string2 = "server.exe"
        $string3 = "9e352eebda58736627852c7e3cc9652b"
        $string4 = "CHENSKY152"
        $string5 = "im523"
        $string6 = "cmd.exe /k ping 0 & del"

    condition:
        uint16(0) == 0x4D5A and 2 of them and filesize < 45KB
}