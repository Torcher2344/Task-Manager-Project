# Web3 Audit Skill (Immunefi / Code4rena)

## EVM methodology
1. Map protocol trust boundaries and privileged roles.
2. Build state transition model for each contract.
3. Identify invariants and economic assumptions.
4. Test edge-case interactions and composability risks.

## Priority issue classes
- Reentrancy (single and cross-function)
- Integer over/underflow and precision loss
- Broken access control / role misconfiguration
- Flash-loan-assisted manipulation
- Oracle manipulation and stale pricing
- Signature replay and permit abuse

## Workflow
- Static review of contracts and inherited dependencies
- Unit/invariant/fuzz testing
- Manual attack-path construction
- Impact quantification and exploitability validation
