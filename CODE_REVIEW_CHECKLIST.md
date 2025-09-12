# DarkHound Code Review Checklist

- [ ] Are all inputs and data sources validated and sanitized?
- [ ] Are errors handled securely (no stack trace/sensitive info leaks)?
- [ ] Are secrets stored securely outside source/config files?
- [ ] Are dependencies pinned and vulnerability scanned?
- [ ] Is threat intelligence data validated before use?
- [ ] Is logging secure and free of sensitive info?
- [ ] Is memory safety enforced in native code?
- [ ] Are hunting queries audited and logged?
- [ ] Are third-party integrations reviewed for security?
- [ ] Are security controls and considerations documented?

## Reviewer Notes
Add security feedback or concerns here.
