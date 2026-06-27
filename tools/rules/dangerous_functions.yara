import "elf"

private rule is_elf_binary {
    condition:
        uint32(0) == 0x464C457F and (elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN)
}

rule dangerous_string_functions {
    meta:
        description = "Imported unsafe string manipulation functions"
        severity = "high"
        cwe = "CWE-120"
        false_positive_control = "ELF import table plus unsafe libc symbol"
    strings:
        $strcpy = "strcpy" ascii
        $strcat = "strcat" ascii
        $sprintf = "sprintf" ascii
        $vsprintf = "vsprintf" ascii
        $gets = "gets" ascii
        $scanf = "scanf" ascii
        $sscanf = "sscanf" ascii
        $fscanf = "fscanf" ascii
    condition:
        is_elf_binary and any of them
}

rule dangerous_memory_functions_without_fortify {
    meta:
        description = "Memory copy functions without visible FORTIFY checked variants"
        severity = "medium"
        cwe = "CWE-122"
    strings:
        $memcpy = "memcpy" ascii
        $memmove = "memmove" ascii
        $strncpy = "strncpy" ascii
        $memcpy_chk = "__memcpy_chk" ascii
        $memmove_chk = "__memmove_chk" ascii
        $strncpy_chk = "__strncpy_chk" ascii
    condition:
        is_elf_binary and any of ($memcpy, $memmove, $strncpy) and not any of ($memcpy_chk, $memmove_chk, $strncpy_chk)
}

rule dangerous_command_execution {
    meta:
        description = "Command execution functions that require taint review"
        severity = "high"
        cwe = "CWE-78"
    strings:
        $system = "system" ascii
        $popen = "popen" ascii
        $execve = "execve" ascii
        $execl = "execl" ascii
        $execle = "execle" ascii
        $execlp = "execlp" ascii
        $execv = "execv" ascii
        $execvp = "execvp" ascii
    condition:
        is_elf_binary and any of them
}

rule dangerous_format_string {
    meta:
        description = "Format functions plus risky format string tokens"
        severity = "high"
        cwe = "CWE-134"
    strings:
        $printf = "printf" ascii
        $fprintf = "fprintf" ascii
        $syslog = "syslog" ascii
        $snprintf = "snprintf" ascii
        $fmt_s = "%s" ascii
        $fmt_n = "%n" ascii
        $fmt_x = "%x" ascii
    condition:
        is_elf_binary and any of ($printf, $fprintf, $syslog, $snprintf) and any of ($fmt_s, $fmt_n, $fmt_x)
}

rule dangerous_temp_files {
    meta:
        description = "Insecure temporary file creation"
        severity = "medium"
        cwe = "CWE-377"
    strings:
        $tmpnam = "tmpnam" ascii
        $tempnam = "tempnam" ascii
        $mktemp = "mktemp" ascii
    condition:
        is_elf_binary and any of them
}

rule dangerous_random {
    meta:
        description = "Weak random number generation"
        severity = "medium"
        cwe = "CWE-330"
    strings:
        $rand = "rand" ascii
        $srand = "srand" ascii
    condition:
        is_elf_binary and any of them
}
