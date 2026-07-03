# Track B Output Contract

Return JSON only. Do not include Markdown, prose, or extra keys outside the contract.

```json
{
  "finding_present": true,
  "finding_status": "candidate | confirmed_static | inconclusive",
  "title": "short finding title",
  "cwe_id": "CWE-000",
  "severity": "critical | high | medium | low | info",
  "confidence": 0.0,
  "location": {
    "binary": "path to affected binary when applicable",
    "function": "function name when known",
    "file": "file path when applicable",
    "address_offset": "0x0 when known"
  },
  "evidence": {
    "description": "evidence summary",
    "source_to_sink": "attacker-controlled source to vulnerable sink, or empty when not applicable",
    "guard_analysis": "why guard is missing, insufficient, or present",
    "supporting_files": []
  },
  "attack_surface": {
    "type": "network | cli | file | ipc | config | env | library",
    "entry_point": "entry point when known"
  },
  "verification": {
    "poc_status": "untested"
  },
  "remediation": {
    "suggestion": "specific remediation tied to evidence",
    "effort": "low | medium | high"
  },
  "references": []
}
```

If evidence is insufficient, return:

```json
{
  "finding_present": false,
  "finding_status": "inconclusive",
  "evidence": {
    "description": "what was checked and what evidence is missing",
    "supporting_files": []
  }
}
```

## Mapping Notes

The executor maps positive responses into `templates/finding.json` and assigns the next `TB-NNN` finding ID. The executor must preserve raw evidence paths in `supporting_files`.
