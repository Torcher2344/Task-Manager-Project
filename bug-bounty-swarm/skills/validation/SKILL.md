# Validation Skill

## 4-Gate Validation Checklist
1. **Reproducibility**
   - PoC works 3/3 attempts in the same environment.
2. **Scope confirmation**
   - Target endpoint and asset are explicitly in scope.
3. **Deduplication check**
   - No existing finding matches vuln class + endpoint + parameter.
4. **CVSS scoring**
   - Attach CVSS v3.1 base score and vector rationale.

## CVSS v3.1 quick table
- Critical: 9.0 - 10.0
- High: 7.0 - 8.9
- Medium: 4.0 - 6.9
- Low: 0.1 - 3.9
- None: 0.0

## Common rejection reasons
- Out-of-scope target
- Non-reproducible behavior
- Duplicate of known issue
- Informational-only with no security impact
- Requires unrealistic attacker assumptions
