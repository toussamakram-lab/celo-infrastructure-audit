# SystemConfig removes the upstream INTEROP-non-disable safety invariant

**Severity:** Informational
**Component:** `packages/contracts-bedrock/src/L1/SystemConfig.sol` (`setFeature`)
**Target:** celo-org/optimism (celo-optimism)

## Bug Description

Upstream OP Stack enforces a safety invariant in `SystemConfig.setFeature`: once the `INTEROP`
feature is enabled, it cannot be disabled. The upstream code enforces this explicitly, with a
comment stating the reason - the OP Contracts Manager (OPCM) relies on this flag staying set to
reject re-migrating a member of an interop set:

```solidity
// Present in upstream OP Stack setFeature():
// INTEROP cannot be disabled as the OPCM relies on it to reject re-migrating a
// member of an interop set.
if (_feature == Features.INTEROP && !_enabled) {
    revert SystemConfig_InvalidFeatureState();
}
```

celo-optimism removed this guard. In the Celo version of `setFeature`, the feature-specific safety
block only retains the `ETH_LOCKBOX` protection (cannot-disable plus a pause check); the `INTEROP`
clause is gone. As a result, on Celo the `INTEROP` feature can be toggled from enabled back to
disabled, which upstream deliberately makes impossible.

The relevant Celo code path (`setFeature`) after the removal:

```solidity
function setFeature(bytes32 _feature, bool _enabled) external {
    // Features can only be set by the ProxyAdmin or its owner.
    _assertOnlyProxyAdminOrProxyAdminOwner();

    if (_enabled == isFeatureEnabled[_feature]) {
        revert SystemConfig_InvalidFeatureState();
    }

    // Handle feature-specific safety logic here.
    if (_feature == Features.ETH_LOCKBOX) {
        if (!_enabled) {
            revert SystemConfig_InvalidFeatureState();
        }
        if (superchainConfig.paused(optimismPortal())) {
            revert SystemConfig_InvalidFeatureState();
        }
    }
    // NOTE: the upstream INTEROP-cannot-be-disabled clause has been removed here.

    isFeatureEnabled[_feature] = _enabled;
    emit FeatureSet(_feature, _enabled);
}
```

This is a relaxation of a safety invariant that upstream enforces at the contract level by design.

## Impact

The direct effect is that an invariant upstream guarantees mathematically (INTEROP, once on, stays
on) is no longer guaranteed on Celo. It is enforced, if at all, only by operational discipline.

Because OPCM uses the `INTEROP` feature flag as the signal that a chain is already a member of an
interop set, removing the on-chain guard creates a dangerous state: if Celo is (or becomes) part
of an OP interop set, governance disabling `INTEROP` could cause OPCM to no longer recognize the
chain as already-migrated, and potentially allow it to be re-migrated. Re-migrating an existing
interop-set member can corrupt interop-set membership and the cross-chain safety assumptions that
depend on it.

Honest scoping of the impact:

- `setFeature` is gated by `_assertOnlyProxyAdminOrProxyAdminOwner()`. Only the ProxyAdmin or its
  owner (governance) can reach this path. It is NOT reachable by an unprivileged attacker.
- The re-migration consequence is conditional. It matters only if Celo actually participates in
  OPCM-managed interop migration. If Celo is a standalone L2 that is not a member of an OP interop
  set, the invariant is not relevant to it and the removal is benign.
- No funds are directly at risk from the removal itself; the concern is an operational footgun and
  a divergence from an upstream safety guarantee that the contract is supposed to enforce on its
  own, independent of governance discipline.

The core point for this report: upstream chose to make this a contract-enforced invariant rather
than a documented operational rule, precisely so that a governance mistake cannot reach the
dangerous state. Celo's removal moves that protection from "cannot happen" to "must be avoided by
process," which is the kind of silent weakening that is easy to miss during an OPCM interaction.

## Risk Breakdown

- Difficulty to Exploit: High (requires a privileged governance action; not attacker-reachable)
- Weakness: Invariant Relaxation / Missing Safety Guard
- Attacker-triggerable: No
- Funds directly at risk: No
- Category: Divergence from an upstream contract-enforced safety invariant

## Recommendation

Choose one of the following, based on whether Celo participates in OPCM interop migration:

1. If Celo is or may become part of an OP interop set: restore the upstream guard so the invariant
   is enforced at the contract level, matching upstream:

   ```solidity
   if (_feature == Features.INTEROP && !_enabled) {
       revert SystemConfig_InvalidFeatureState();
   }
   ```

2. If Celo is a standalone L2 that is intentionally not subject to OPCM interop migration: document
   the divergence explicitly (a `@notice` on `setFeature` and a note in the deploy/config docs)
   stating that the INTEROP-non-disable invariant is intentionally dropped and why it is safe for
   Celo, so future maintainers do not assume the upstream guarantee still holds.

## References

- celo-optimism: `packages/contracts-bedrock/src/L1/SystemConfig.sol` (`setFeature`)
- Upstream OP Stack: `SystemConfig.sol` `setFeature` (contains the INTEROP-non-disable clause that
  Celo removed)
