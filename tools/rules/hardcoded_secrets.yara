rule hardcoded_passwords_with_context {
    meta:
        description = "Potential hardcoded credentials with assignment context"
        severity = "high"
        cwe = "CWE-798"
    strings:
        $key1 = "password" ascii nocase
        $key2 = "passwd" ascii nocase
        $key3 = "api_key" ascii nocase
        $key4 = "token" ascii nocase
        $assign1 = "=" ascii
        $assign2 = ":" ascii
        $quote = """ ascii
    condition:
        any of ($key*) and any of ($assign*) and $quote
}

rule hardcoded_private_keys {
    meta:
        description = "Embedded private keys or certificates"
        severity = "critical"
        cwe = "CWE-321"
    strings:
        $rsa_key = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $ec_key = "-----BEGIN EC PRIVATE KEY-----" ascii
        $dsa_key = "-----BEGIN DSA PRIVATE KEY-----" ascii
        $generic_key = "-----BEGIN PRIVATE KEY-----" ascii
        $encrypted_key = "-----BEGIN ENCRYPTED PRIVATE KEY-----" ascii
    condition:
        any of them
}

rule hardcoded_aws_keys_with_secret_context {
    meta:
        description = "AWS access key with nearby secret-key context"
        severity = "critical"
        cwe = "CWE-798"
    strings:
        $aws_access = /AKIA[0-9A-Z]{16}/ ascii
        $aws_secret_label1 = "aws_secret_access_key" ascii nocase
        $aws_secret_label2 = "secretAccessKey" ascii nocase
        $aws_secret_label3 = "AWS_SECRET_ACCESS_KEY" ascii
        $aws_secret_value = /[A-Za-z0-9\/+=]{40}/ ascii
    condition:
        $aws_access and any of ($aws_secret_label*) and $aws_secret_value
}

rule high_entropy_strings_context_limited {
    meta:
        description = "High entropy strings only when credential context is present"
        severity = "low"
        cwe = "CWE-321"
    strings:
        $context1 = "secret" ascii nocase
        $context2 = "token" ascii nocase
        $context3 = "private" ascii nocase
        $base64_long = /[A-Za-z0-9+\/]{80,}={0,2}/ ascii
        $hex_long = /[0-9a-fA-F]{96,}/ ascii
    condition:
        filesize < 20MB and any of ($context*) and any of ($base64_long, $hex_long)
}
