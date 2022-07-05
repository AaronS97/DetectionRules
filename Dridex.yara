rule Dridex {
    meta: 
        Author: "Aaron S." 
        Date Created: "4 Jul 2022"
        Version: "1.0"
        Description: "Simple rule for detecting dridex malware EXE/DLL"

    strings:
        $pe_magic_num = "MZ"
        $string1 = "Dormittjd.dll"
        $string2 = "Gpernfedeefe.pdb"
        $string3 = "3H5N5T5Z5`5f5l5r5x5"
        $string4 = "Dihzeh Reofqehs"

    condition:
        $pe_magic_num at 0 and $string1 and $string2 and $string3 and $string4
}