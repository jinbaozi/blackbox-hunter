# Validation

Run:

```bash
python3 tests/report/test_report_generator.py
bash tests/validate_report_template.sh
bash tests/validate_full_workflow.sh
bash tests/validate_python.sh
```

Expected results:

- Generated Markdown reports contain Chinese sections such as `## 执行摘要`, `## 发现项生命周期汇总`, and `## 附录证据路径`.
- Old English section names such as `Executive Summary` and `Findings by Lifecycle` do not appear in generated Markdown.
- Lifecycle display values are localized while JSON artifacts, artifact paths, and technical identifiers remain compatible.
