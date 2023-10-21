import "hash"

rule Redline {
    meta: 
        Author = "Aaron S." 
        Date_Created = "19 Aug 2022"
        Version = "1.0"
        Description = "Simple rule for detecting Redline stealer malware"

    strings:
        $pe_magic_num = "MZ"
        $string1 = "Happy.exe"
        $string2 = "Implosions.exe"
        $string3 = "Yandex\\YaAddon"
        $string4 = "WanaLife"

    condition:
        $pe_magic_num at 0 and $string1 and $string2 and $string3 and $string4 or hash.md5
}
