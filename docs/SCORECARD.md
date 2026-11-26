# Scorecard

Overall **1.4 / 5** (mean of the five surface scores: 3, 2, 1, 0, 1).
Scale 0-5 per surface (0 = no protection and no design; 5 = migrated,
measured, and operated). Dimensions: measurement completeness,
in-tree support, migration design, operational readiness.

| Surface | Score | Measurement | In-tree support | Migration design | Operational readiness |
|---------|-------|-------------|-----------------|------------------|-----------------------|
| Validator identity and manifests | 3 | 5 | 4 | 2 | 2 |
| Key generation | 2 | 4 | 3 | 1 | 2 |
| Key rotation and revocation | 1 | 4 | 1 | 1 | 1 |
| Compromise detection and recovery | 0 | 3 | 0 | 0 | 0 |
| Post-quantum readiness | 1 | 5 | 0 | 2 | 1 |

## Reading

- **Validator identity and manifests (3)** is the strongest surface: the format, verification, revocation, and the live inventory are all measured and traced to source. It is capped by the version-0 lock and the missing PQ upgrade path.
- **Key generation (2)** works, but only for one algorithm, hardcoded in three places, through a path that warns about its own secret handling.
- **Key rotation and revocation (1)**: the semantics are specified and live rotation is observed, but nothing automates it, schedules it, or creates manifests outside tests.
- **Compromise detection and recovery (0)**: the weakest surface. Nothing detects compromise; recovery from master-key compromise is terminal by design.
- **Post-quantum readiness (1)**: rates and size impacts are freshly measured and modelled, but zero PQ support exists in-tree and the 32-146x size blow-up has no designed mitigation.

Machine data: `data/scorecard.json`.
