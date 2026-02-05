rule TestRule
{
    strings:
        $my_string = "Malware"
    condition:
        $my_string
}