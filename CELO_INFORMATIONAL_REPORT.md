# BatchAuthenticator accepts smart-contract batchers, causing an op-node liveness halt

**Severity:** Informational / Low
**Component:** `packages/contracts-bedrock/src/L1/BatchAuthenticator.sol` <-> `op-node/rollup/derive` (Espresso batch authentication)
**Status:** Requires privileged governance action to trigger; recoverable by governance. Not attacker-exploitable.

---

## Summary

There is an undocumented coupling between two layers of the Espresso batch-authentication
design:

- **On-chain**, `BatchAuthenticator.authenticateBatchInfo` emits
  `BatchInfoAuthenticated(commitment, msg.sender)` and permits the batcher
  (`espressoBatcher`, or the fallback `SystemConfig` batcher) to be set to **any address**,
  including a smart contract such as a Safe multisig.
- **Off-chain**, `op-node` authenticates a batch only if the EOA that *signed the batch-inbox
  transaction* equals the `caller` recorded in that event. A batch-inbox transaction is a plain
  signed L1 transaction, so its sender (`tx.From`) is **always an EOA** - a contract has no
  private key and cannot originate an L1 transaction.

If governance sets the batcher to a contract address, the on-chain `caller` (the contract) can
never equal the inbox transaction's `tx.From` (an EOA). Every batch then fails authentication,
and L2 derivation stalls until governance reverts the change.

This is a real architectural mismatch worth documenting and guarding, but it is reachable only
through a privileged, deliberate misconfiguration and is recoverable, hence the Informational /
Low rating.

## Affected code

**Contract - emits `msg.sender`, accepts any batcher address**
`src/L1/BatchAuthenticator.sol`:

```solidity
// authenticateBatchInfo (abridged)
address activeEspressoBatcher = espressoBatcher();
if (msg.sender != activeEspressoBatcher) {
    revert UnauthorizedEspressoBatcher(msg.sender, activeEspressoBatcher);
}
...
emit BatchInfoAuthenticated(_commitment, msg.sender);   // caller == msg.sender
```

`setEspressoBatcher(address _newEspressoBatcher)` (onlyOwner) and `initialize(...)` validate only
that the batcher is non-zero - they do not require it to be an EOA.

**op-node - requires inbox tx sender == event caller**
`op-node/rollup/derive/data_source.go` (`isBatchTxAuthorized`, ~line 200):

```go
authCaller, ok := authenticatedHashes[batchHash]
if !ok { ... return false }
sender, err := dsCfg.l1Signer.Sender(tx)   // EOA that signed the batch-inbox tx
if err != nil { ... return false }
if sender != authCaller {                   // contract batcher: EOA != contract, always fails
    ... return false
}
return true
```

The `authCaller` value originates from the event's indexed `caller` (`Topics[1]`), collected in
`batch_authenticator.go` (`collectAuthEventsFromReceipts`).

## Impact

**L2 liveness halt while the batcher is a contract.** Once Espresso event-authentication is
enforced, no batch can pass `isBatchTxAuthorized`, so the derivation pipeline accepts no new
batch data and the safe chain stops advancing.

Scope and limits of the impact:

- **Not a safety issue.** No invalid or forged batch is accepted; the failure mode is rejection,
  not injection. Funds and state integrity are unaffected.
- **Not attacker-triggerable.** `setEspressoBatcher` is `onlyOwner`; the fallback batcher is set
  through `SystemConfig` governance. An external attacker cannot set the batcher.
- **Recoverable, not permanent.** Governance can restore liveness by setting the batcher back to
  an EOA (`setEspressoBatcher`) or switching batcher mode (`setActiveIsEspresso`). The halt lasts
  only until that corrective transaction lands.
- **Consistent with a pre-existing OP Stack assumption.** Upstream authorization
  (`isAuthorizedBatchSender`) already recovers the inbox tx's EOA and compares it to the
  configured batcher, so a contract batcher never worked upstream either. This finding is that the
  new contract does not *prevent* the misconfiguration, and that the coupling is undocumented.

## Proof of concept

A Foundry test (`packages/contracts-bedrock/test/L1/BatchAuthenticatorDoS.t.sol`) deploys the
authenticator with a mock smart-contract batcher and shows the emitted `caller` is the contract
address, not the relaying EOA (`tx.origin`) - exactly the inequality op-node rejects on.

Sequence:

1. Governance sets the batcher to a contract address (`setEspressoBatcher(multisig)` / fallback
   `batcherHash = multisig`).
2. The multisig calls `authenticateBatchInfo(commitment, sig)`; the contract emits
   `BatchInfoAuthenticated(commitment, caller = address(multisig))`.
3. op-node recovers `tx.From` of the batch-inbox transaction - necessarily an EOA - and compares
   it to `caller`.
4. `EOA != multisig` => `isBatchTxAuthorized` returns false => the batch is rejected. With every
   batch from this batcher rejected, derivation halts.

The test asserts `emittedCaller == address(multisig)` and
`emittedCaller != tx.origin (the relaying EOA)`, isolating the contract-side half of the
mismatch. A second baseline test shows an EOA batcher emits itself as `caller`, which *can* equal
the inbox tx's `tx.From`, so EOA batchers authenticate correctly.

Run output:

```
Ran 2 tests for test/L1/BatchAuthenticatorDoS.t.sol:BatchAuthenticatorDoS_Test
[PASS] test_contractBatcher_emitsContractAsCaller_notTxOrigin_succeeds()
[PASS] test_eoaBatcher_emitsSelfAsCaller_succeeds()
Suite result: ok. 2 passed; 0 failed; 0 skipped
```

Note: this test proves the contract-side behavior (the emitted `caller` is the contract address,
distinct from the relaying EOA). It does not execute op-node; the chain-halt conclusion follows
from `isBatchTxAuthorized` combined with the fact that an inbox transaction's `tx.From` is always
an EOA. A full end-to-end proof would require an op-node derivation test feeding a real inbox
transaction.

## Recommendation

Reject contract batchers at configuration time so the misconfiguration cannot take effect:

```solidity
// In setEspressoBatcher(...) and initialize(...), for a non-zero batcher:
if (_batcher.code.length != 0) revert BatcherMustBeEOA(_batcher);
```

Caveats to weigh before adopting the exact check above:

- **EIP-7702 (Pectra).** A delegated EOA carries code, so `code.length != 0` would also reject a
  legitimate 7702-style batcher. If such batchers are to be supported, this check is too strict;
  consider instead documenting the EOA requirement and validating it operationally, or checking
  specifically for the 7702 delegation prefix.
- **Deploy-after-set.** `code.length` reflects only the moment of the setter call; an address
  empty at set time could later receive code (e.g. CREATE2). The check is a guardrail against the
  obvious footgun, not a complete guarantee.

At minimum, document the EOA requirement at both layers: a `@notice` on `setEspressoBatcher` /
`initialize`, and a comment in `op-node/rollup/derive` noting that the batcher must be the EOA that
signs batch-inbox transactions. This makes the off-chain/on-chain coupling explicit for future
maintainers and operators.

## References

- `packages/contracts-bedrock/src/L1/BatchAuthenticator.sol` - `authenticateBatchInfo`,
  `setEspressoBatcher`, `initialize`
- `op-node/rollup/derive/data_source.go` - `isBatchTxAuthorized`
- `op-node/rollup/derive/batch_authenticator.go` - `collectAuthEventsFromReceipts`,
  `CollectAuthenticatedBatches`
- `packages/contracts-bedrock/test/L1/BatchAuthenticatorDoS.t.sol` - proof of concept

---

# Secondary (Informational): SystemConfig removes the INTEROP-non-disable guard

**Severity:** Informational
**Component:** `packages/contracts-bedrock/src/L1/SystemConfig.sol` (`setFeature`)
**Status:** Governance-gated; not attacker-reachable. Divergence from upstream safety invariant.

## Summary

Upstream OP Stack forbids disabling the `INTEROP` feature once enabled, because OPCM relies on
that invariant to reject re-migrating a member of an interop set:

```solidity
// Present upstream, REMOVED in celo-optimism's setFeature():
// if (_feature == Features.INTEROP && !_enabled) revert SystemConfig_InvalidFeatureState();
```

celo-optimism deleted this guard, so on Celo the `INTEROP` feature can be toggled off.

## Impact

`setFeature` is gated by `_assertOnlyProxyAdminOrProxyAdminOwner()` — only the ProxyAdmin or its
owner (governance) can call it, so this is **not attacker-reachable**. The risk, if any, is a
governance footgun: if Celo is subject to OPCM interop migration, disabling `INTEROP` could let
OPCM re-migrate the chain and corrupt interop-set membership. If Celo is a standalone L2 not in an
OP interop set, the guard is irrelevant and its removal is benign/intentional. The retained
ETH_LOCKBOX safety logic (cannot-disable + pause check) is unaffected.

## Recommendation

Confirm with the team whether the removal was intentional and whether Celo participates in OPCM
interop migration. If it does, restore the guard; if not, document the deliberate divergence.

## References

- `packages/contracts-bedrock/src/L1/SystemConfig.sol` - `setFeature`
- Upstream OP Stack `SystemConfig.sol` (for the diff showing the removed guard)
