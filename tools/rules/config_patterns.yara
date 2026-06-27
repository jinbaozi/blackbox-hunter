rule suspicious_service_config
{
  meta:
    description = "Potentially unsafe service or daemon configuration"
    severity = "medium"
  strings:
    $world_writable = /chmod\s+777/
    $privileged = /User\s*=\s*root/
    $shell_exec = /Exec(Start|Reload|Stop).*\/(ba|z|c)?sh/
  condition:
    any of them
}

rule exposed_debug_config
{
  meta:
    description = "Debug or development configuration exposed in package"
    severity = "low"
  strings:
    $debug1 = /debug\s*=\s*(true|1|yes)/ nocase
    $debug2 = /log[_-]?level\s*=\s*(debug|trace)/ nocase
    $bind_all = /0\.0\.0\.0:[0-9]{2,5}/
  condition:
    any of them
}
