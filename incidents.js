/* InfiniteSecurity — Independent CEX Incident Prevention & Autonomous Code Forensics Dossier
   4-Tab Forensic Workbench, MITRE ATT&CK Kill Chains, 4-Tier Active Defense,
   Interactive Human-vs-AI Loss-Containment Simulator, and 32-Incident Empirical Reference Ledger.
   Zero personal data, zero internal client identifiers. */

(function () {
  "use strict";

  // ==================== 1. 10 DEEP-DIVE CEX INCIDENTS ====================
  const INCIDENTS = [
    {
      id: "binance-2026",
      venue: "Binance",
      date: "Oct 29, 2026",
      category: "oss_supply",
      catLabel: "Outdated OSS & Supply Chain + Signing Seam",
      color: "var(--c-sign)",
      lossReported: "~$6.3B gross (multi-B frozen)",
      attacker: "DPRK APT (TraderTraitor / Lazarus cluster)",
      mitreTags: ["T1195.002 Supply Chain", "T1078 Valid Accounts", "T1565.001 Tx Redirection", "EIP-7702 0x04"],
      humanFailure: "Multi-month dev-tool / tampered package compromise -> lateral pivot into internal wallet-signing service -> EIP-7702 (0x04) hot-wallet redirection while manual SIEM missed slow dwell time.",
      interceptionLayer: "Lane 1 SBOM Lock + Lane 3 EIP-7702 Guard (`inspect_eip7702_transaction`) + Order-to-Payload HSM Digest",
      autonomyPct: 96,
      autonomyLabel: "96% Autonomous (0-human millisecond block on 0x04 delegation & order mismatch)",
      modeledOutcome: "Blocked at signing boundary (modeled >98% loss prevention; 0 core master keys ever exposed)",
      timeline: [
        { t: "Jun–Sep 2026", txt: "Historical: Tampered developer tools & job-lure packages established multi-month covert persistence across DevOps environments.", intercept: false },
        { t: "Oct 29 · T-0s", txt: "InfiniteSecurity Autonomous Stop: `inspect_eip7702_transaction()` rejects unauthorized EIP-7702 `type=0x04` delegation AND `verify_order_to_evm_payload_digest()` refuses signing requests lacking a signed customer withdrawal ledger Merkle proof.", intercept: true },
        { t: "T + 2s", txt: "InfiniteSecurity Containment: Auto-isolates rogue internal signing service pod via CACAO playbook while keeping verified retail withdrawal pipelines 100% open.", intercept: false }
      ],
      vulnFilename: "signing_service/evm_dispatcher.py (Vulnerable Internal Signing Seam)",
      vulnCode: `# Vulnerable internal wallet-signing service trusts upstream RPC requests blindly:
# Master keys stayed inside HSMs, yet a subverted signing service still directed funds!
def sign_internal_request(rpc_req: dict, hsm_signer):
    # [ISSUE 1] Accepts EIP-7702 SET_CODE_TX (type == 0x04) EOA code delegation!
    #           One signed 0x04 authorization lets an attacker hijack hot-wallet routing.
    tx_type = rpc_req.get("type", 2)

    # [ISSUE 2] Zero cryptographic proof binding raw calldata (recipient, amount)
    #           back to an authentic customer withdrawal order in the User Ledger!
    raw_tx = build_evm_tx(
        tx_type=tx_type,
        to=rpc_req["to"],
        value=rpc_req.get("value", 0),
        authorization_list=rpc_req.get("auth_list", []),
        data=rpc_req["data"],
    )
    # [ISSUE 3] HSM signs opaque 32-byte digest with no velocity or Merkle invariant:
    return hsm_signer.sign_blind_hash(keccak256(raw_tx))`,
      safeFilename: "cybersecurity/crypto/evm_guards.py (InfiniteSecurity Autonomous HSM Boundary)",
      safeCode: `from cybersecurity.crypto.evm_guards import (
    inspect_eip7702_transaction,
    verify_order_to_evm_payload_digest,
)

# Runs out-of-band at the HSM signing boundary (<200ms, 0 unilateral keys held):
def autonomous_hsm_gate(raw_tx: dict, ledger_order: dict, ledger_merkle_proof: str):
    # 1. Zero-human hard block on ANY EIP-7702 (type=0x04) custody EOA delegation
    eip7702_verdict = inspect_eip7702_transaction(
        tx_type=raw_tx["type"],
        authorization_tuples=raw_tx.get("authorization_list", ()),
        trusted_delegation_targets=(),  # Empty = zero EOA code delegation permitted
    )
    if not eip7702_verdict.admissible:
        return trigger_autonomous_block("BLOCK_EIP7702_DELEGATION", eip7702_verdict.reasons)

    # 2. Cryptographically bind raw EVM calldata recipient/amount to signed user-ledger proof
    digest_verdict = verify_order_to_evm_payload_digest(
        expected_recipient=ledger_order["recipient"],
        expected_amount_raw=ledger_order["amount_raw"],
        calldata_hex=raw_tx["data"],
        ledger_merkle_proof=ledger_merkle_proof,
    )
    if not digest_verdict.admissible:
        return trigger_autonomous_block("BLOCK_FORGED_INTERNAL_ORDER", digest_verdict.reasons)

    # 3. Verify T+0 outflow velocity stays inside LLR-CUSUM hot-wallet envelope
    return "ALLOW_SIGN"`,
      issues: [
        { sev: "CRITICAL", title: "Subverted Internal Signing Service Bypasses Hardware Key Isolation", detail: "Core master keys never leaked; adversaries compromised the upstream orchestration service feeding unsigned payloads into HSMs and abused EIP-7702 delegation.", fix: "Autonomous HSM-boundary guard blocks `tx_type == 0x04` and demands an independent User-Ledger Merkle debit proof on every signature." },
        { sev: "HIGH", title: "Multi-Month Dwell Time Inside Compromised Dev Tools", detail: "Tampered developer packages sat undetected across build pipelines for months before triggering large-scale routing redirects.", fix: "Reachable SBOM provenance pins SHA-256 package digests and severs direct DevOps-to-signing-plane IAM paths in CI." }
      ],
      mitreKillChain: [
        { tactic: "Initial Access (TA0001)", technique: "T1195.002 Supply Chain", attackerAction: "Delivered tampered dev utility / job-lure package to internal engineers.", humanBlindSpot: "Unranked SCA alerts drowned out tampered transitive packages.", aiStop: "Layer 1 Reachable SBOM + SHA-256 package lock blocks unattested builds.", latency: "< 45 sec (CI)" },
        { tactic: "Lateral Movement (TA0008)", technique: "T1078 Valid Accounts", attackerAction: "Pivoted slowly over months into internal wallet-signing service.", humanBlindSpot: "Low-and-slow credential use blended into baseline SIEM traffic.", aiStop: "Layer 2 Zero-Direct-Access IAM BFS isolates signing service pods from dev identities.", latency: "Pre-deploy" },
        { tactic: "Impact (TA0040)", technique: "EIP-7702 (0x04) & T1565", attackerAction: "Submitted EIP-7702 EOA code delegation + forged hot-wallet transfer orders.", humanBlindSpot: "HSM signed valid internal API schema without inspecting delegation type or ledger proof.", aiStop: "Layer 3 `inspect_eip7702_transaction()` + `verify_order_to_evm_payload_digest()` auto-rejects.", latency: "< 200 ms" },
        { tactic: "Containment", technique: "Multi-Chain Burst", attackerAction: "Attempted high-velocity withdrawal sweeps before human freeze.", humanBlindSpot: "Manual coordination across chains took minutes while funds moved.", aiStop: "Layer 5 LLR-CUSUM isolates compromised pod via CACAO playbook; retail withdrawals stay live.", latency: "< 3 sec" }
      ],
      activeDefense: {
        tier1: "FIDO2/Passkey + Hardware-attested mTLS identity for signing orchestrators; zero static cloud keys.",
        tier2: "Cryptographic User-Ledger Merkle proof required before hot/warm HSM evaluates any digest.",
        tier3: "Out-of-band EVM byte decoder enforces `tx_type != 0x04` and exact recipient/amount match.",
        tier4: "Scoped per-minute outflow velocity cap (<5% hot float) with automatic pod quarantine.",
        walletCap: "Hot Wallet <5% float (MPC/HSM), Warm 2-of-3 intra-day, Cold >90% air-gapped 3-of-5.",
        reconciliation: "Continuous T+0 User Ledger vs. On-Chain hot balance reconciliation triggers Safe Mode on first unbacked debit.",
        activeMechanism: "Automated CACAO isolation playbook revokes rogue orchestrator credentials in <3s without halting verified retail exits."
      },
      counterfactual: {
        humanMttd: "Multi-month dwell + manual cross-chain freeze coordination",
        humanLoss: "~$6.3B gross (multi-B frozen via post-facto emergency actions)",
        humanTouchpoints: "15+ manual SIEM / war-room / signing reviews",
        humanUptime: "Emergency cross-chain withdrawal halts",
        aiLatency: "< 200 ms deterministic pre-sign block",
        aiLoss: "$0 modeled on EIP-7702 & forged orders (>98% loss prevented)",
        aiTouchpoints: "0 runtime human bottlenecks",
        aiUptime: "100% verified retail withdrawal SLAs preserved (12/12)",
        receiptJson: `{\n  "engine": "InfiniteSecurity v2.4",\n  "gate": "HSM_BOUNDARY_EIP7702_AND_LEDGER_PROOF",\n  "decision": "BLOCK_SIGNING",\n  "reasons": ["FORBIDDEN_EIP7702_TYPE_0x04", "MISSING_LEDGER_MERKLE_DEBIT_PROOF"],\n  "latency_ms": 118,\n  "unilateral_key_access": "NONE",\n  "customer_withdrawal_sla": "12/12_PRESERVED"\n}`
      }
    },
    {
      id: "bybit-2025",
      venue: "Bybit",
      date: "Feb 21, 2025",
      category: "blind_sign",
      catLabel: "Blind Signing + Outdated PyYAML Supply Chain",
      color: "var(--c-web)",
      lossReported: "$1.4B–$1.5B (401,347 ETH)",
      attacker: "Lazarus Group (TraderTraitor / UNC4899 — FBI attributed)",
      mitreTags: ["T1566 Phishing", "T1190 PyYAML RCE", "T1003 ~/.aws Dump", "T1565.001 _app.js Tamper"],
      humanFailure: "Safe{Wallet} developer ran LinkedIn job-scam Docker repo (`MC-Based-Stock-Invest-Simulator-main`) exploiting unsafe `PyYAML` RCE -> stolen `~/.aws` session token overwrote S3 `_app-52c9031bfa03da47.js` -> 3 human signers blind-signed `DELEGATECALL` to `0x9622...7242` overwriting Safe `slot[0]`.",
      interceptionLayer: "Lane 1 PyYAML/IAM BFS + Lane 2 S3 WORM/SRI Lock + Lane 3 10-Word Safe `debug_traceCall` (`stateOverrides`)",
      autonomyPct: 98,
      autonomyLabel: "98% Autonomous (Blocked at 3 independent machine gates before hardware tap)",
      modeledOutcome: "100% cold-vault takeover prevented pre-signature (modeled >$1.45B saved; warm sweeps stay live)",
      timeline: [
        { t: "Feb 4, 2025", txt: "Historical: Safe{Wallet} developer ran `MC-Based-Stock-Invest-Simulator-main` Docker lure -> `PyYAML` `yaml.load()` RCE connected to C2 (`getstockprice[.]com`), dropped Poseidon/MythicAgents in RAM, and exfiltrated `~/.aws/credentials` session tokens.", intercept: false },
        { t: "Feb 19, 2025", txt: "Historical: Attacker ran `aws s3 sync` to tamper production `_app-52c9031bfa03da47.js` on S3: conditionally targeted only Bybit's cold wallet, saved the real tx UI object, swapped payload to `operation=1 (DELEGATECALL)`, then restored fake UI display post-sign.", intercept: false },
        { t: "Feb 21 · 14:13 UTC", txt: "InfiniteSecurity Autonomous Stop: `evm_rpc_trace.py` simulates unsigned `0x6a761202` via `stateOverrides` (`threshold=1`, pre-validated `v=1` sig bypassing `GS020`), detects `operation=1` + Safe `slot[0x00]` (`masterCopy`) overwrite -> `0x9622...7242` and HARD-BLOCKS signing in <200ms (2 minutes before attackers wiped the JS).", intercept: true }
      ],
      vulnFilename: "safe_ui/_app-52c9031bfa03da47.js & lure/loader.py (Exact 5-Step Exploit Pattern)",
      vulnCode: `# 1. Feb 4 Entry Vector on Safe{Wallet} Developer Workstation (MC-Based-Stock-Invest-Simulator):
import yaml
# [ISSUE 1] Unsafe PyYAML FullLoader RCE executes attacker shell & steals ~/.aws/credentials:
cfg = yaml.load(download_yaml_from_c2(), Loader=yaml.FullLoader)

// 2. Feb 19 Tampered S3 Production JS (_app-52c9031bfa03da47.js — 5-Step Swap Mechanics):
async function hookedSignSafeTx(safeAddress, originalTxData) {
  if (safeAddress !== TARGET_BYBIT_COLD_WALLET) return signNormally(originalTxData);
  const savedUiDisplay = structuredClone(originalTxData);        // Step 2: Keep benign UI copy
  const maliciousTx = {                                          // Step 3: Swap calldata!
    to: "0x96221423681A1ed520188Eb4E749a65965667242",            // Attacker sweepETH impl
    value: "0",
    operation: 1,                                                // DELEGATECALL overwrites slot[0]!
    data: "0xa9059cbb..."
  };
  const sig = await ledgerHardwareWallet.signBlindHash(maliciousTx); // Step 4: Blind sign!
  return { ...savedUiDisplay, signature: sig };                  // Step 5: Hide swap from co-signers!
}`,
      safeFilename: "cybersecurity/adapters/evm_rpc_trace.py (InfiniteSecurity Out-of-Band Verifier)",
      safeCode: `from cybersecurity.adapters.evm_rpc_trace import trace_and_verify_safe_tx

# Runs independently of Safe{Wallet} web UI (0 private keys held) BEFORE Signer #1 touches Ledger:
receipt = trace_and_verify_safe_tx(
    rpc_url=MAINNET_ARCHIVE_RPC,
    safe_address=COLD_SAFE_ADDRESS,
    calldata_hex=unsigned_0x6a761202_hex,
    whitelisted_recipients=[APPROVED_WARM_WALLET],
    # Injects threshold=1 & pre-validated v=1 simulation sig via stateOverrides (bypasses GS020!):
    trace_mode="state_override_exec",
    timeout_s=3.0,  # Fail-closed -> HOLD_TRACE_UNAVAILABLE if RPC degrades
)

# Machine verifier independently detects ALL FOUR invariants simultaneously (<200ms):
#   [1] FORBIDDEN_DELEGATECALL: operation == 1 to non-MultiSendCallOnly target
#   [2] PROTECTED_SLOT_MUTATION: Safe slot[0x00] singleton overwritten -> 0x9622...7242
#   [3] CONTRADICTORY_UI_CLAIM: browser claimed routine ETH transfer, hex executes proxy takeover
#   [4] S3_STATIC_ASSET_DRIFT: live _app-*.js SHA-384 != signed CI manifest (auto-quarantined)
assert receipt.status == "VERIFIED_SAFE" and receipt.allow_sign is True`,
      issues: [
        { sev: "CRITICAL", title: "5-Step Frontend JS Swap Defeated 3-of-N Hardware Multisig", detail: "Because hardware screens displayed opaque 32-byte SafeTx hashes, 3 executives faithfully signed a `DELEGATECALL` overwriting Safe `slot[0]` (`masterCopy`) while seeing a normal warm transfer in Chrome.", fix: "Out-of-band 10-word Safe ABI + `debug_traceCall` `stateOverrides` verifier exposes exact `(contract, slot)` writes in <200ms before any key signs." },
        { sev: "CRITICAL", title: "Direct Dev AWS S3 Write Privilege + Unsafe PyYAML RCE", detail: "A single developer laptop held an AWS STS token with direct `s3:PutObject` write permission to the production static signing bucket (`aws s3 sync`).", fix: "Layer 1 IAM BFS blocks personal S3 write edges; Layer 2 enforces S3 Object Lock (WORM), strict CSP, SHA-384 SRI pinning, and `yaml.safe_load()`." }
      ],
      mitreKillChain: [
        { tactic: "Initial Access (TA0001)", technique: "T1566 / T1190", attackerAction: "Job scam sent `MC-Based-Stock-Invest-Simulator-main` Docker project triggering `PyYAML` `yaml.load()` RCE.", humanBlindSpot: "Developer executed untrusted repo on work machine holding prod AWS profile.", aiStop: "Layer 1 AST/SBOM policy forbids `PyYAML<6.0` / `FullLoader`; workstation isolated from prod IAM.", latency: "< 45 sec (CI)" },
        { tactic: "Credential Access (TA0006)", technique: "T1003 / T1078", attackerAction: "Poseidon/MythicAgents in RAM dumped `~/.aws/credentials` (12h STS session tokens) via ExpressVPN.", humanBlindSpot: "Valid AWS session token bypassed MFA and remained undetected Feb 5–19.", aiStop: "Layer 2 Zero-Direct-Access CI/CD ensures personal AWS sessions have zero `s3:PutObject` edges.", latency: "Pre-deploy" },
        { tactic: "Impact — UI Tamper (TA0040)", technique: "T1565.001 Data Manip.", attackerAction: "Used `aws s3 sync` on Feb 19 to inject conditional swap into `_app-52c9031bfa03da47.js` (deleted 2 min post-hack).", humanBlindSpot: "No continuous SHA-384 static asset integrity check on S3 production bundle.", aiStop: "Layer 2 S3 Object Lock (WORM) + continuous Static Asset Integrity monitor trips Safe Mode on hash drift.", latency: "< 5 sec" },
        { tactic: "Impact — Blind Sign (TA0040)", technique: "Safe slot[0] Takeover", attackerAction: "Feb 21 14:13 UTC: 3 executives blind-signed `DELEGATECALL` transferring 401,347 ETH (~$1.5B).", humanBlindSpot: "Signers trusted browser UI; unsigned Safe call reverts (`GS020`) on naive simulators.", aiStop: "Layer 3 Out-of-Band `debug_traceCall` (`stateOverrides`) catches `op=1` + `slot[0]` mutation -> HARD BLOCK.", latency: "< 200 ms" }
      ],
      activeDefense: {
        tier1: "Hardened developer workstations (no personal web/email), FIDO2 hardware keys, and Zero-Direct-Access GitOps.",
        tier2: "Strict Segregation of Duties (Maker Ops -> Checker Security -> Approver Executive) with out-of-band Intent Verification.",
        tier3: "WYSIWYS Out-of-Band verifier independently proves `(Recipient, Amount, Asset, operation==0, 0 control-slot diffs)` before hardware tap.",
        tier4: "S3 Object Lock (WORM) + SHA-384 SRI pinning + <3s automated cold/warm withdrawal Kill-Switch.",
        walletCap: "Cold Wallet (>90%) requires air-gapped 3-of-5 quorum + independent OOB simulation receipt; Warm/Hot strictly capped.",
        reconciliation: "Continuous Static Asset Integrity check on S3/CDN + T+0 Ledger-vs-Blockchain balance reconciliation.",
        activeMechanism: "Even if all developer laptops and S3 buckets are breached simultaneously, Layer 3 refuses signing on `slot[0]` mutation (0 keys lost)."
      },
      counterfactual: {
        humanMttd: "17-day AWS dwell; malicious JS wiped 2 min after 14:13 UTC drain",
        humanLoss: "$1.4B–$1.5B (401,347 ETH drained in single takeover)",
        humanTouchpoints: "3 executive blind-sign approvals + 0 independent bytecode checks",
        humanUptime: "Emergency multi-billion bridge loan required to honor withdrawals",
        aiLatency: "< 200 ms pre-signature storage-slot hard block",
        aiLoss: "$0 (cold vault singleton `slot[0]` never mutated)",
        aiTouchpoints: "0 human hex inspection required (machine verdict = BLOCK)",
        aiUptime: "100% normal warm & customer withdrawals live (12/12)",
        receiptJson: `{\n  "engine": "InfiniteSecurity Pre-Signing Verifier",\n  "safe": "0x1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4",\n  "decision": "BLOCK_SIGNING",\n  "violations": ["FORBIDDEN_DELEGATECALL(op=1)", "PROTECTED_SLOT_MUTATION(slot[0x00]->0x9622...7242)"],\n  "trace_mode": "debug_traceCall_stateOverrides_v1",\n  "latency_ms": 164,\n  "unilateral_key_access": "NONE"\n}`
      }
    },
    {
      id: "upbit-2025",
      venue: "Upbit (Solana 2025 & ETH 2019)",
      date: "Nov 27, 2025 (+ Nov 2019 / Nov 2026 Context)",
      category: "crypto_key",
      catLabel: "Outdated / Custom Crypto Library (Ed25519 Nonce Bias)",
      color: "var(--c-ai)",
      lossReported: "~$30–37M (44.5B KRW Solana, 2025) + $50M ETH (2019)",
      attacker: "Suspected Lazarus Group (Remote HNP / LLL Lattice Key Extraction)",
      mitreTags: ["Cryptanalysis HNP/LLL", "Ed25519 LSB Nonce Bias", "400ms Solana Drain", "T1078 Key Recovery"],
      humanFailure: "Internally modified / non-standard Solana Ed25519 MPC signing replaced deterministic RFC 8032 nonces (`k = H(H(d)||m)`) with biased randomized DKG shares (`k = k1+k2+k3`, 4–8-bit LSB/MSB bias); attackers mined public Solana txs to solve HNP via LLL lattice reduction and drained SOL, USDC, BONK, JUP, RAY, RENDER, ORCA, PYTH in 54 minutes at 400ms block speeds. (Note: Nov 2026 Upbit CYBER suspension was an external bridge mint alert, not an Upbit library flaw.)",
      interceptionLayer: "Lane 1 OSS/Crypto Library Gate + Lane 4 FROST RFC 8032, ZKP Nonce Proof, MTD & Honey-Nonces + `<3s` Entropy Breaker",
      autonomyPct: 95,
      autonomyLabel: "95% Autonomous (Blocked in CI via 1,000-sig LLL stress test + <3s Solana burst halt)",
      modeledOutcome: "Private key never recoverable (100% prevented pre-deploy); if deployed, <3s burst cap limits loss to <2% of hot float",
      timeline: [
        { t: "Pre-Deploy CI", txt: "InfiniteSecurity Autonomous Stop #1: PR dependency & crypto gate rejects custom/outdated randomized Ed25519 crate, enforces audited `frost-ed25519` + per-node ZKP nonce proofs, and runs automated 1,000-sig 256-bit bit-bias + LLL self-attack test -> blocks merge (`EXIT 2 RESTRICT`).", intercept: true },
        { t: "Nov 27 · 04:42 KST", txt: "Historical (Nov 27, 2025): Public Solana signatures `(R, s)` satisfied `s_i = k_i + e_i * d (mod L)` with 4–8-bit biased `k_i`. Attackers solved the Hidden Number Problem (HNP) via LLL lattice shortest-vector reduction to extract private key `d` and drain 8+ SPL token classes across 54 minutes.", intercept: false },
        { t: "T + 3 sec", txt: "InfiniteSecurity Autonomous Stop #2: Continuous On-Chain Entropy Reconciliation + Moving Target Defense (hourly MPC resharing) + Honey-Nonces + `<3s` LLR-CUSUM Solana circuit breaker halts drain in 3s vs. 54 minutes.", intercept: true }
      ],
      vulnFilename: "solana_wallet/mpc_ed25519.rs (Broken Non-Deterministic Ed25519 MPC Math)",
      vulnCode: `// Standard RFC 8032 Ed25519 is DETERMINISTIC: k = H(H(d) || m) -> immune to RNG bias!
// Signature equation:  R = [k]G,   s = (k + H(R, PK, m) * d) mod L
//
// [ROOT CAUSE] Custom/outdated MPC coordinator replaced determinism with randomized DKG shares:
//              k = k_server1 + k_server2 + k_server3
pub fn sign_solana_mpc_biased(d_share: Scalar, msg: &[u8]) -> (Point, Scalar) {
    // [ISSUE 1] Weak/flawed PRNG introduces 4-8 bit LSB/MSB or small-value bias (< 2^248):
    let k_i: Scalar = legacy_rng_248bit_biased();   // Ideal bit mean = 0.500; biased = 0.08!

    // [ISSUE 2] Zero per-node ZKP proving k_i uniformity & zero pre-broadcast entropy gate!
    // [ISSUE 3] Static long-lived shares let attackers harvest ~1,000 public Solana txs:
    //           k_j = s_j - e_j * d (mod L)  ->  LLL Lattice Shortest Vector recovers private key d!
    // [ISSUE 4] Single Solana hot key controls dozens of SPL Associated Token Accounts (ATA)!
    combine_unchecked_shares(d_share, k_i, msg)
}`,
      safeFilename: "infinitesec_gates/ed25519_frost_mtd_guard.py (InfiniteSecurity 4-Tier Cryptographic Defense)",
      safeCode: `# InfiniteSecurity CI + Continuous Active Cryptographic Assurance (0 human dependency):
def autonomous_ed25519_assurance(cargo_lock: dict, sample_sigs: list[bytes], mpc_cluster) -> str:
    # Tier 1/2 (Pre-Deploy CI): Block custom/outdated Ed25519 crates; mandate FROST + ZKP nonce proofs
    if "mpc-eddsa-legacy" in cargo_lock or not cargo_lock.get("frost-ed25519", "").startswith("2."):
        return "RESTRICT: Upgrade to audited frost-ed25519 >= 2.1.0 with per-node ZKP nonce proofs"

    # Tier 3 (Cryptographic Entropy Audit & Self-LLL Stress Test before mainnet broadcast):
    bit_means = compute_256bit_nonce_distribution(sample_sigs)   # Expected: 0.500 +/- 0.015 per bit
    if max(abs(m - 0.5) for m in bit_means) > 0.015 or run_lll_bkz_self_probe(sample_sigs).leaked:
        mpc_cluster.freeze_and_rotate_keys(reason="ED25519_NONCE_BIT_BIAS_DETECTED")
        return "HOLD: Nonce bias detected -> MPC reshare + clean HSM key rotation triggered!"

    # Active Defense: Hourly Moving Target Defense (MPC Resharing d_i -> d'_i) invalidates
    # any collected lattice dataset + Honey-Nonces decoy wallet traps remote blockchain scanners!
    mpc_cluster.schedule_hourly_resharing_mtd(keep_public_key=True)
    deploy_honey_nonce_canary_wallet(alert_action="AUTO_LOCK_PRIMARY_SOLANA_HOT_WALLET")

    # Tier 4 (Business Logic): Per-SPL-asset hot caps (<5%) + <3s LLR-CUSUM 400ms Solana breaker
    return "SHIP: FROST RFC 8032 + ZKP + MTD Resharing + <3s Solana Circuit Breaker Active"`,
      issues: [
        { sev: "CRITICAL", title: "Breaking Ed25519 Determinism Reintroduces ECDSA Lattice Key Theft", detail: "Ed25519 was designed by D.J. Bernstein specifically to eliminate random-nonce flaws (`k = H(H(d)||m)`). Switching to randomized MPC DKG with a 4–8-bit LSB/MSB bias turned public Solana signatures into an off-chain HNP/LLL private-key oracle.", fix: "CI crypto gate enforces audited FROST RFC 8032, requires per-node ZKP nonce uniformity proofs, and runs automated LLL/BKZ self-stress tests." },
        { sev: "CRITICAL", title: "Solana 400ms Block Speed & Multi-SPL Key Blast Radius Outrun Humans", detail: "One Solana key controlled SOL, USDC, BONK, JUP, RAY, RENDER, ORCA, and PYTH; 400ms blocks drained ~44.5B KRW across 54 minutes before manual response isolated the wallet.", fix: "Segregated per-asset hot keys (<5% cap), hourly MTD MPC resharing, Honey-Nonces, and `<3s` LLR-CUSUM burst circuit breakers halt drains before humans wake up." }
      ],
      mitreKillChain: [
        { tactic: "Reconnaissance (TA0043)", technique: "Public Chain Harvesting", attackerAction: "Passively scraped thousands of public Upbit Solana `(R, s)` signatures on-chain with zero network intrusion.", humanBlindSpot: "Traditional EDR/firewalls see zero alerts when attackers analyze public blockchain data.", aiStop: "Layer 4 On-Chain Entropy Reconciliation scans our own emitted signatures continuously; Honey-Nonces trap scanners.", latency: "Continuous" },
        { tactic: "Credential Access (TA0006)", technique: "HNP + LLL Lattice", attackerAction: "Modeled 4–8-bit LSB nonce bias in `k_i = s_i - e_i*d (mod L)` and ran LLL shortest-vector reduction to extract `d`.", humanBlindSpot: "Annual manual audits never ran statistical 256-bit bit-bias or LLL tests on MPC signing builds.", aiStop: "Layer 1/4 CI runs automated 1,000-sig bit-bias + LLL self-probe; FROST + ZKP nonce proofs + hourly MTD resharing.", latency: "< 45s CI / Hourly MTD" },
        { tactic: "Execution (TA0002)", technique: "Valid Key Withdrawal", attackerAction: "04:42 KST Nov 27, 2025: signed legitimate-looking withdrawals across SOL + 7+ SPL token ATAs.", humanBlindSpot: "On-chain transactions carried valid Ed25519 signatures matching the hot wallet key.", aiStop: "Layer 5 Cryptographic State & Transaction Flow Reconciliation flags valid-signature txs absent from approved Ledger DB.", latency: "< 2 sec" },
        { tactic: "Exfiltration (TA0010)", technique: "400ms Burst Drain", attackerAction: "Drained ~44.5B KRW ($30–37M) across 54 minutes before manual suspension & cold sweep.", humanBlindSpot: "Human on-call escalation at 04:42 KST could not react inside 400ms Solana block intervals.", aiStop: "Layer 5 `<3s` LLR-CUSUM burst circuit breaker freezes compromised SPL hot wallet automatically.", latency: "< 3 sec" }
      ],
      activeDefense: {
        tier1: "Device & Identity Tier: Dual geographic HSM + biometric attestation (e.g., Seoul + Singapore) required to activate MPC shares.",
        tier2: "MPC Threshold & ZKP Tier: Every signing node emits a Zero-Knowledge Proof proving `k_i` came from clean HSM CSPRNG with zero bit bias.",
        tier3: "Cryptographic Audit Tier: Independent Entropy Gatekeeper blocks broadcast of any signature failing 256-bit uniformity or self-LLL check.",
        tier4: "Business Logic Tier: Dynamic value caps (Low=auto, Medium=SecOps, High=Board physical quorum) + automatic Lockdown on burst.",
        walletCap: "Segregated Solana keys per token tier (<5% hot float); never reuse one hot key across dozens of SPL ATAs or multiple chains.",
        reconciliation: "Three continuous loops: Entropy Reconciliation (lattice distance), Cryptographic State Reconciliation (fault detection), and T+0 Flow Reconciliation (unapproved valid signatures).",
        activeMechanism: "Moving Target Defense (hourly MPC share resharing invalidating collected lattice datasets) + Honey-Nonces decoy wallets trapping remote cryptanalysts."
      },
      counterfactual: {
        humanMttd: "54-minute Solana drain at 04:42 KST before manual suspension",
        humanLoss: "~$30–37M (44.5B KRW across SOL/USDC/BONK/JUP/RAY/RENDER/ORCA/PYTH)",
        humanTouchpoints: "Manual cryptographic audit gaps + 04:42 KST human incident triage",
        humanUptime: "Full Solana deposit/withdrawal suspension during cold migration",
        aiLatency: "Pre-deploy CI block (<45s) + runtime <3s circuit breaker",
        aiLoss: "$0 pre-deploy (FROST + ZKP); <$600K (<2% hot cap) even if deployed runtime-only",
        aiTouchpoints: "0 human intervention required to halt biased signatures or burst drain",
        aiUptime: "Non-affected chains & verified retail withdrawals stay 100% live",
        receiptJson: `{\n  "engine": "InfiniteSecurity Cryptographic Assurance Gate",\n  "crate": "mpc-eddsa-legacy@0.4.2 -> REJECTED",\n  "bit_bias_max_dev": 0.418,\n  "lll_self_probe": "KEY_RECOVERED_IN_14.2S",\n  "decision": "RESTRICT_AND_TRIGGER_FROST_UPGRADE",\n  "mtd_reshare_interval_min": 60,\n  "unilateral_key_access": "NONE"\n}`
      }
    },
    {
      id: "bitget-2026",
      venue: "Bitget (Sep 2026 Vendor Breach & Apr 2025 VOXEL Loop)",
      date: "Sep 24, 2026 & Apr 20, 2025",
      category: "oss_supply",
      catLabel: "3rd-Party Vendor Vulnerability + Lag-0 Clearing Loop",
      color: "var(--c-code)",
      lossReported: "~$387.5M (Sep 2026) + $100M VOXEL anomaly (Apr 2025)",
      attacker: "Lazarus / TraderTraitor (Sep 2026); Trading Syndicate (Apr 2025)",
      mitreTags: ["T1199 Trusted Relationship", "T1078 Forged Admin JWT", "11-Chain Burst", "Lag-0 MM Feedback"],
      humanFailure: "Sep 2026: Flaw in an integrated third-party security product gave weeks of silent dwell time -> forged withdrawal commands injected into internal management platform across 11 chains. Apr 2025: Thin perp market-maker bot entered an unchecked Lag-0 quote feedback loop printing phantom PnL.",
      interceptionLayer: "Lane 2 StateFence Vendor Airlock + Lane 3 Ledger-to-HSM Proof + Lane 5 LLR-CUSUM `ClearingGroup` Clamp",
      autonomyPct: 95,
      autonomyLabel: "95% Autonomous (Rejects forged vendor commands + clamps MM loop in <3s)",
      modeledOutcome: "Forged multi-chain commands auto-blocked at HSM seam; Lag-0 MM loop clamped before phantom PnL withdraws",
      timeline: [
        { t: "Aug–Sep 2026", txt: "Historical (Sep 2026): Vulnerability inside third-party security software granted elevated internal network access for weeks prior to multi-chain withdrawal injection.", intercept: false },
        { t: "Sep 24 · T-0s", txt: "InfiniteSecurity Autonomous Stop: Even if an internal management platform or security vendor tool is fully compromised, `verify_order_to_evm_payload_digest()` refuses withdrawals without an independent signed Customer Ledger balance debit + multi-chain velocity quorum.", intercept: true },
        { t: "Apr 2025 · <3s", txt: "InfiniteSecurity Autonomous Stop (VOXEL): Explicit Lag-0 `ClearingGroup` + Page's LLR-CUSUM detects one-sided MM fill asymmetry and clamps MM bot spread/inventory in <3s while retail spot stays 100% live.", intercept: true }
      ],
      vulnFilename: "ops_platform/withdrawal_router.py & mm_bot/quoter.py (Vulnerable Patterns)",
      vulnCode: `# 1. Sep 2026 Pattern: Management platform trusts JWTs stolen via 3rd-party security tool:
def process_management_withdrawal(cmd: dict, hot_wallet_cluster):
    # [ISSUE 1] Broad internal credentials grant 3rd-party security agent pivot into ops plane!
    if verify_internal_jwt(cmd["auth_token"]):
        # [ISSUE 2] No independent User-Ledger debit Merkle proof & no 11-chain burst cap!
        for chain_tx in cmd["batch_11_chains"]:
            hot_wallet_cluster.sign_and_broadcast(chain_tx)

# 2. Apr 2025 VOXEL Pattern: Perp market-maker bot lacks Lag-0 feedback-loop clamp:
def on_orderbook_fill(fill):
    # [ISSUE 3] Thin-book fill shifts mid-price instantaneously, triggering self-reinforcing loop:
    new_quote = fill.price * (1.002 if fill.side == "BUY" else 0.998)
    exchange_api.place_unchecked_mm_order(new_quote, size=MAX_MM_SIZE)`,
      safeFilename: "cybersecurity/twin/rollout.py & evm_guards.py (InfiniteSecurity Autonomous Defense)",
      safeCode: `# 1. Zero-Trust Withdrawal Airlock: 3rd-party / ops tools NEVER unilaterally trigger HSM signing
def autonomous_withdrawal_airlock(cmd: dict, user_ledger_db, cusum_monitor):
    # Independently verify cryptographic customer debit proof BEFORE hot/warm HSM signs:
    if not user_ledger_db.verify_signed_debit_merkle_proof(
        cmd["order_id"], cmd["amount"], cmd["dest"]
    ):
        return trigger_autonomous_lockdown("FORGED_MANAGEMENT_COMMAND_NO_LEDGER_PROOF")

    # Enforce global multi-chain velocity ceiling (stops 11-chain simultaneous drain in <3s):
    if cusum_monitor.update_multichain_burst(cmd["usd_value"], cmd["chain"]) == "ALARM_BURST":
        return trigger_scoped_hot_pause(preserve_small_retail_withdrawals=True)
    return "ALLOW_SCOPED_SIGN"

# 2. Explicit Lag-0 ClearingGroup MM Clamp (stops VOXEL-style phantom PnL in <3s):
if clearing_group_cusum(mm_inventory_drift, fill_asymmetry_ratio) > THRESHOLD:
    apply_minimal_cut("act.clamp_mm_bot_inventory_and_spread")  # Retail markets stay 100% live!`,
      issues: [
        { sev: "CRITICAL", title: "Third-Party Security Tool Becomes God-Mode Lateral Pivot", detail: "Granting third-party security agents over-privileged internal credentials turns one vendor CVE into forged multi-chain withdrawal commands across 11 chains.", fix: "Read-only least-privilege vendor network isolation + mandatory independent User-Ledger Merkle debit proof verified at the HSM boundary." },
        { sev: "HIGH", title: "Unbounded Lag-0 Matching-Engine <-> MM Bot Feedback Loops", detail: "Without simultaneous `ClearingGroup` drift modeling, thin-book fills print tens of millions in phantom PnL before humans intervene.", fix: "Automated LLR-CUSUM fill-asymmetry detection executes surgical MM inventory clamps in <3s with zero spot-market downtime." }
      ],
      mitreKillChain: [
        { tactic: "Initial Access (TA0001)", technique: "T1199 Trusted Vendor", attackerAction: "Exploited vulnerability in integrated third-party security software for weeks of dwell time.", humanBlindSpot: "Vendor security agent was whitelisted across internal management subnets.", aiStop: "Layer 1/2 IAM BFS enforces zero write/command paths from vendor monitoring planes to custody orchestrators.", latency: "Pre-deploy" },
        { tactic: "Execution (TA0002)", technique: "Forged Multi-Chain Cmd", attackerAction: "Injected forged withdrawal instructions targeting 11 blockchains simultaneously.", humanBlindSpot: "Management API trusted internal JWTs without verifying corresponding customer balance debits.", aiStop: "Layer 3 HSM-boundary check requires cryptographic User-Ledger Merkle proof on every payout.", latency: "< 200 ms" },
        { tactic: "Impact (TA0040)", technique: "Multi-Chain Drain / MM Loop", attackerAction: "Drained ~$387.5M across 11 chains (Sep 2026); exploited unchecked MM loop on VOXEL perp (Apr 2025).", humanBlindSpot: "Manual risk-ops investigation took minutes while automated bots extracted liquidity.", aiStop: "Layer 5 Cross-Chain LLR-CUSUM + Lag-0 `ClearingGroup` clamp isolates rogue channel in <3s.", latency: "< 3 sec" }
      ],
      activeDefense: {
        tier1: "Strict Zero-Trust microsegmentation: third-party security tools receive read-only telemetry mirrors via PrivateLink, never write tokens.",
        tier2: "Independent Customer Ledger debit Merkle proof checked inside isolated withdrawal airlock before signing.",
        tier3: "Cross-chain outflow budget aggregates USD velocity across all 11+ chains simultaneously (no per-chain blind spot).",
        tier4: "Lag-0 `ClearingGroup` real-time simulator detects one-sided MM fill anomalies and clamps bot quotes atomically.",
        walletCap: "Aggregate hot-wallet outflow cap across all chains + per-market MM inventory circuit breaker.",
        reconciliation: "Real-time T+0 Ledger-vs-Chain reconciliation + continuous perp mark-price vs. index-price PnL invariant.",
        activeMechanism: "Scoped CACAO isolation freezes only the forged vendor API channel or rogue MM bot ID — 12/12 retail flows stay open."
      },
      counterfactual: {
        humanMttd: "Weeks of vendor dwell time + manual multi-chain freeze",
        humanLoss: "~$387.5M (Sep 2026) + $100M gross VOXEL anomaly (Apr 2025)",
        humanTouchpoints: "Vendor trust assumptions + manual multi-chain/market-risk intervention",
        humanUptime: "Multi-chain withdrawal pauses & post-trade rollbacks",
        aiLatency: "< 200 ms ledger-proof block / < 3 sec MM loop clamp",
        aiLoss: "$0 on unbacked forged commands; MM phantom PnL clamped <$250K",
        aiTouchpoints: "0 human intervention required to reject unbacked commands",
        aiUptime: "100% legitimate retail spot & withdrawals remain live",
        receiptJson: `{\n  "engine": "InfiniteSecurity Withdrawal Airlock + ClearingGroup",\n  "decision": "BLOCK_FORGED_MULTICHAIN_BATCH",\n  "chains_targeted": 11,\n  "ledger_merkle_proof": "MISSING_INVALID",\n  "cusum_mm_clamp": "ARMED_LT_3S",\n  "unilateral_key_access": "NONE"\n}`
      }
    },
    {
      id: "mixin-2023",
      venue: "Mixin Network",
      date: "Sep 23, 2023",
      category: "cloud_logic",
      catLabel: "Cloud Web2 DB Breach + PyYAML Supply Chain",
      color: "var(--c-vault)",
      lossReported: "$200M (ETH, BTC, ERC-20)",
      attacker: "Lazarus Group (PyYAML RCE -> GCP DB & GCS)",
      mitreTags: ["T1566.002 LinkedIn Lure", "T1059 PyYAML RCE", "T1528 Session Token", "T1565.001 GCS Tamper"],
      humanFailure: "DevOps/SRE engineer ran LinkedIn job-test lure (`MC-Based-Stock-Invest-Simulator-main.zip`, `PyYAML` RCE) -> stolen long-lived GCP session token bypassed MFA -> tampered centralized User Ledger DB & Cloud Storage `_app-.js` so MPC auto-signed $200M drains; forced 50% user haircut.",
      interceptionLayer: "Lane 1 Zero-Direct-Access CI/CD + Lane 2 Static Asset Integrity + Lane 5 T+0 Ledger-vs-Blockchain Reconciler",
      autonomyPct: 94,
      autonomyLabel: "94% Autonomous (Auto-trips Safe Mode on static hash drift or first $1M delta)",
      modeledOutcome: "Blocks static JS & DB tampering pre-signing; T+0 reconciler halts outflow on first $1M delta (modeled >95% loss reduction)",
      timeline: [
        { t: "Initial Access", txt: "Historical: DevOps/SRE executed LinkedIn coding test (`MC-Based-Stock-Invest-Simulator-main.zip`) with unsafe `PyYAML`, leaking GCP session tokens and SSH keys.", intercept: false },
        { t: "Cloud Tamper", txt: "InfiniteSecurity Autonomous Stop #1: IAM BFS forbids direct personal workstation writes to GCP Cloud Storage & Production DB; Static Asset Integrity hash detects any unauthorized `_app-.js` drift immediately.", intercept: true },
        { t: "04:00 UTC+8 · T+3s", txt: "InfiniteSecurity Autonomous Stop #2: Continuous T+0 Ledger-vs-Blockchain reconciler detects on-chain debit without matching user-signed ledger entry -> auto-engages Safe Mode on first delta instead of losing $200M.", intercept: true }
      ],
      vulnFilename: "gcp_ops/terraform_gcs_db.tf & worker/mpc_loop.py (Vulnerable Hybrid Architecture)",
      vulnCode: `# 1. Vulnerable GCP IAM allows personal SRE laptop direct writes to production GCS & DB:
resource "google_storage_bucket_iam_member" "sre_direct_prod_write" {
  bucket = "mixin-prod-static-wallet-ui"
  role   = "roles/storage.objectAdmin"          # [ISSUE 1] Direct overwrite of _app-.js!
  member = "user:sre-engineer@corp.internal"    # Stolen long-lived GCP token bypasses MFA!
}

# 2. Flawed Hybrid Model: Centralized Cloud DB feeds MPC auto-signer with ZERO reconciliation:
def mpc_auto_sign_loop():
    for row in cloud_db.query("SELECT dest, amt FROM pending_withdrawals"):
        # [ISSUE 2] Tampered Cloud DB row triggers automatic MPC drain across ETH/BTC/SOL!
        # [ISSUE 3] Zero Static Asset SHA-384 verification & zero T+0 Ledger-vs-Chain delta check!
        mpc_signer.sign_and_broadcast(row.dest, row.amt)`,
      safeFilename: "infinitesec_policies/zero_direct_cloud_reconcile.py (InfiniteSecurity Autonomous Guard)",
      safeCode: `# 1. Layer 1 Terraform Plan BFS Gate forbids personal workstation writes to prod GCS/DB:
assert not bfs_path_exists(
    iam_graph, source="dev_or_sre_workstation", target="prod_gcs_or_ledger_db"
)

# 2. Layer 2 & 5 Continuous Static Asset Integrity + T+0 Ledger-vs-Blockchain Reconciler:
def autonomous_t0_reconcile(signed_user_ledger, onchain_state, live_gcs_hashes):
    # Immediately catch unauthorized _app-.js modification on Cloud Storage:
    if live_gcs_hashes != SIGNED_GITOPS_MANIFEST_SHA384:
        return engage_autonomous_safe_mode("STATIC_CLOUD_ASSET_TAMPERED")

    # Compare immutable user-signed withdrawal intents vs. live blockchain outflows:
    unbacked_delta_usd = abs(
        onchain_state.hot_balance_usd - signed_user_ledger.expected_hot_balance_usd
    )
    if unbacked_delta_usd > MAX_T0_TOLERANCE_USD:   # e.g., $1M hard tripwire
        # Cuts MPC hot-signing path autonomously before $200M drains (modeled >95% saved):
        return engage_autonomous_safe_mode(f"LEDGER_CHAIN_DRIFT_\${unbacked_delta_usd:,.0f}")
    return "RECONCILED_OK"`,
      issues: [
        { sev: "CRITICAL", title: "Hybrid Centralization Single Point of Failure Defeated MPC", detail: "MPC key sharding failed to stop a $200M drain because the centralized GCP database feeding withdrawal orders into MPC was tampered.", fix: "Multi-cloud split FROST shards (AWS + Azure + On-Prem) + independent signed user-ledger proofs + continuous T+0 Ledger-vs-Blockchain reconciliation." },
        { sev: "HIGH", title: "Long-Lived Cloud Session Tokens + Direct Prod Bucket Writes", detail: "Stolen GCP session tokens bypassed MFA and let attackers push tampered static JavaScript directly to Cloud Storage without CI/CD review.", fix: "Short-lived Workload Identity Federation (TTL 15m), Zero-Direct-Access GitOps, WORM Object Lock, and continuous SHA-384 static asset checks." }
      ],
      mitreKillChain: [
        { tactic: "Initial Access (TA0001)", technique: "T1566.002 Spearphishing", attackerAction: "Sent malicious job-test repo (`MC-Based-Stock-Invest-Simulator-main.zip`) to SRE via LinkedIn/Telegram.", humanBlindSpot: "Engineer executed untrusted Python project on workstation holding GCP creds.", aiStop: "Layer 1 blocks unsafe `PyYAML` patterns; hardened workstations isolated from prod IAM.", latency: "< 45s CI" },
        { tactic: "Credential Access (TA0006)", technique: "T1528 Session Hijack", attackerAction: "Harvested long-lived GCP session tokens & SSH keys, bypassing interactive MFA.", humanBlindSpot: "Long-lived cloud tokens lacked device-bound JIT elevation & IP allowlisting.", aiStop: "Layer 2 enforces 15-min ephemeral WIF/IRSA tokens + PrivateLink-only PAM/JIT.", latency: "Pre-deploy" },
        { tactic: "Impact — Tamper (TA0040)", technique: "T1565.001 Stored Data", attackerAction: "Modified centralized User Ledger DB records and static `_app-.js` on Google Cloud Storage.", humanBlindSpot: "No Data-at-Rest cryptographic signature check on static cloud assets or DB intents.", aiStop: "Layer 2 Static Asset Integrity check trips Safe Mode instantly on any unauthorized GCS change.", latency: "< 5 sec" },
        { tactic: "Exfiltration (TA0010)", technique: "Automated MPC Drain", attackerAction: "MPC auto-signed $200M across ETH/BTC/ERC-20 before staff spotted balance drop.", humanBlindSpot: "Manual reconciliation caught the drain only after $200M left via multi-chain DEXs.", aiStop: "Layer 5 T+0 Ledger-vs-Blockchain Reconciler auto-halts MPC on first $1M discrepancy.", latency: "< 3 sec" }
      ],
      activeDefense: {
        tier1: "Zero-Direct-Access CI/CD: IAM denies all personal writes to GCS/DB; 15-min ephemeral WIF/IRSA credentials only.",
        tier2: "Multi-cloud split FROST/MPC architecture (AWS + Azure + On-Premise HSM) removes single cloud-provider SPOF.",
        tier3: "Static Asset Reconciliation verifies cryptographic SHA-384 manifests of every production JS bundle continuously.",
        tier4: "Moving Target Defense (periodic MPC resharing) + automated <3s Safe Mode Kill-Switch.",
        walletCap: "Triple-Layer Wallet: Hot (<5% MPC), Warm (2-of-3 intra-day), Cold (>90% air-gapped 3-of-5 physical quorum).",
        reconciliation: "Continuous T+0 Ledger-vs-Blockchain reconciliation + signed Data-at-Rest integrity verification.",
        activeMechanism: "Automatically engages Safe Mode on the first unbacked $1M debit — preventing catastrophic 50% customer haircuts."
      },
      counterfactual: {
        humanMttd: "Detected only after $200M drained across ETH/BTC/SOL",
        humanLoss: "$200M stolen (users faced prolonged freeze & 50% cash haircut)",
        humanTouchpoints: "Direct SRE cloud rights + manual balance inspection",
        humanUptime: "Full Mixin Kernel deposit/withdrawal suspension",
        aiLatency: "< 5s Static Asset hash block / < 3s T+0 ledger drift cutoff",
        aiLoss: "$0 on GCS tamper; <=$1M cap on DB tamper (>95% loss prevented)",
        aiTouchpoints: "0 human intervention needed to trip Safe Mode",
        aiUptime: "Unaffected chains remain isolated and verifiable",
        receiptJson: `{\n  "engine": "InfiniteSecurity Cloud Integrity & T+0 Reconciler",\n  "decision": "ENGAGE_SAFE_MODE",\n  "trigger": "STATIC_GCS_SHA384_DRIFT + LEDGER_CHAIN_DELTA_EXCEEDED",\n  "max_delta_tolerance_usd": 1000000,\n  "unilateral_key_access": "NONE"\n}`
      }
    },
    {
      id: "wazirx-2024",
      venue: "WazirX",
      date: "Jul 18, 2024",
      category: "blind_sign",
      catLabel: "Multi-Sig UI Manipulation & Blind Signing",
      color: "var(--c-web)",
      lossReported: "$230M (~45% of exchange reserves)",
      attacker: "Lazarus Group (Liminal Custody UI Discrepancy)",
      mitreTags: ["T1565.001 UI Spoofing", "Safe Proxy Upgrade", "Blind Signing 4-of-6", "EIP-1967 Slot Mutation"],
      humanFailure: "4 of 6 multisig signers saw legitimate transfer details in Liminal's custody UI while actually signing a Gnosis Safe implementation upgrade pointing to an attacker contract — draining ~45% of total exchange reserves.",
      interceptionLayer: "Lane 3 Independent 10-Word Safe ABI Decoder + `debug_traceCall` Proxy Slot Verifier",
      autonomyPct: 98,
      autonomyLabel: "98% Autonomous (Catches UI-vs-calldata discrepancy across all 4 signers pre-tap)",
      modeledOutcome: "100% prevented prior to 1st signature (zero proxy implementation upgrade executed)",
      timeline: [
        { t: "Pre-Signing", txt: "Historical: Payload rendered inside third-party custody web portal diverged completely from raw Safe `execTransaction` hex bytes pushed to hardware wallets.", intercept: false },
        { t: "Signer 1 · T-0s", txt: "InfiniteSecurity Autonomous Stop: Independent Out-of-Band decoder (`evm_guards.verify_safe_multisig_execution`) rejects `operation=1` + EIP-1967 / Safe `slot[0]` implementation swap -> flags `CONTRADICTORY_UI_CLAIM` before Signer #1 ever touches a button.", intercept: true },
        { t: "Post-Check", txt: "Custody operations continue normal whitelisted ERC-20 transfers (`operation=0`) with zero reserve loss and zero restructuring.", intercept: false }
      ],
      vulnFilename: "custody_ui/liminal_signer_flow.ts (Vulnerable Same-Origin Trust Pattern)",
      vulnCode: `// Signers verify intent inside the SAME web UI / third-party custodian portal submitting the tx:
async function approveMultisigTransfer(txProposal: CustodyUiProposal) {
  // Browser renders benign summary: "Transfer 100,000 USDT -> Internal Wallet"
  // Actual hex sent to all 4 signers: Safe.execTransaction(op=1, to=ATTACKER_UPGRADE_CONTRACT)
  // [ISSUE 1] No out-of-band raw-byte ABI decoding independent of the custody vendor UI!
  // [ISSUE 2] No simulation of storage slot[0] (masterCopy) or EIP-1967 implementation slot!
  if (confirm(\`Approve \${txProposal.uiLabel}?\`)) {
    return hardwareWallet.signBlindHash(txProposal.rawSafeTxHash); // 4-of-6 quorum hijacked!
  }
}`,
      safeFilename: "cybersecurity/scripts/infinitesec_cli.py (Independent Out-of-Band WYSIWYS Check)",
      safeCode: `# Executed on an independent verifier (0 private keys held) BEFORE any signer approves:
$ infinitesec check-tx \\
    --safe 0x27fd43babfbe83a81d14665b1a6fb8030a60c9b4 \\
    --calldata 0x6a761202... \\
    --whitelist 0x1111...1111 \\
    --rpc-url https://eth-mainnet.rpc.internal

# Deterministic Machine Output (EXIT 2 BLOCKED_VIOLATION · latency 142ms):
#   [1] FORBIDDEN_DELEGATECALL: operation=1 to unverified implementation contract
#   [2] PROTECTED_SLOT_MUTATION: Safe slot[0x00] / EIP-1967 implementation mutated!
#   [3] CONTRADICTORY_UI_CLAIM: UI label != decoded EVM state diff
#   -> ALL 4 HARDWARE SIGNERS BLOCKED BEFORE 1ST SIGNATURE`,
      issues: [
        { sev: "CRITICAL", title: "4-of-6 Multisig Fails When All Signers Trust One Compromised UI", detail: "Adding more human signers provides zero protection if every signer inspects the same manipulated custody web dashboard.", fix: "Out-of-band `infinitesec check-tx` decodes all 10 Safe head words + simulated storage diffs on an isolated verifier." },
        { sev: "HIGH", title: "Silent Proxy Implementation Upgrade Bypasses Token Allowlists", detail: "Because the upgrade happened via `DELEGATECALL` to a custom implementation contract, transfer-amount limits never fired.", fix: "Protected `(contract, slot)` invariant monitors all 8 Safe/EIP-1967 control slots and blocks unauthorized upgrades fail-closed." }
      ],
      mitreKillChain: [
        { tactic: "Resource Dev (TA0042)", technique: "Malicious Safe Impl", attackerAction: "Deployed attacker upgrade contract designed to overwrite Safe `slot[0]` and sweep ERC-20 reserves.", humanBlindSpot: "Contract address was invisible inside browser-rendered transfer summary.", aiStop: "Layer 3 decodes raw `to`, `operation`, and simulated target bytecode independently.", latency: "< 150 ms" },
        { tactic: "Impact — UI Discrepancy", technique: "T1565.001 Blind Sign", attackerAction: "Presented benign transfer UI to 4-of-6 signers while routing malicious upgrade payload to signers.", humanBlindSpot: "Signers verified human-readable fields inside the compromised vendor dashboard.", aiStop: "Layer 3 Out-of-Band WYSIWYS verifier flags `CONTRADICTORY_UI_CLAIM` + `PROTECTED_SLOT_MUTATION`.", latency: "< 200 ms" },
        { tactic: "Exfiltration (TA0010)", technique: "45% Reserve Sweep", attackerAction: "Upgraded proxy and drained $230M across SHIB, ETH, MATIC, PEPE, USDT.", humanBlindSpot: "Once 4 signatures landed on-chain, takeover was atomic and irreversible.", aiStop: "Blocked prior to Signer #1 tap -> $0 drained; zero insolvency restructuring.", latency: "Pre-sign (T-0s)" }
      ],
      activeDefense: {
        tier1: "Zero-trust custody vendor boundary: third-party portal output is treated as untrusted UI metadata.",
        tier2: "Out-of-band WYSIWYS verification screen displays machine-decoded `(to, op, token, amount, storageDiff)` independently.",
        tier3: "Hard cryptographic ban on `operation=1` outside canonical `MultiSendCallOnly` (`0x40A2...130D`).",
        tier4: "Mandatory 24-hour governance timelock on any legitimate proxy implementation or signer-quorum upgrade.",
        walletCap: "Cold/warm reserve separation ensures no single multisig upgrade can expose 45% of exchange assets.",
        reconciliation: "Pre-sign `debug_traceCall` storage-slot diff + post-execution T+0 reserve reconciliation.",
        activeMechanism: "Fail-closed pre-signature gate blocks proxy takeover at Signer #1 with zero human hex-reading required."
      },
      counterfactual: {
        humanMttd: "Atomic on-chain proxy takeover after 4 blind signatures",
        humanLoss: "$230M (~45% of total exchange reserves; prolonged restructuring)",
        humanTouchpoints: "4 human multisig signers + custody vendor co-sign",
        humanUptime: "Platform halted; multi-month legal restructuring",
        aiLatency: "< 150 ms deterministic ABI & storage-slot block",
        aiLoss: "$0 (blocked before 1st signature)",
        aiTouchpoints: "0 human raw-hex verification needed",
        aiUptime: "100% customer operations uninterrupted",
        receiptJson: `{\n  "engine": "InfiniteSecurity Safe 10-Word Decoder",\n  "decision": "BLOCK_SIGNING",\n  "reasons": ["FORBIDDEN_DELEGATECALL", "PROTECTED_SLOT_MUTATION(slot[0x00])", "CONTRADICTORY_UI_CLAIM"],\n  "latency_ms": 142,\n  "unilateral_key_access": "NONE"\n}`
      }
    },
    {
      id: "dmm-2024",
      venue: "DMM Bitcoin",
      date: "May 31, 2024",
      category: "blind_sign",
      catLabel: "APT Social Engineering -> Custody Parameter Spoofing",
      color: "var(--c-sign)",
      lossReported: "$305M (4,502.9 BTC)",
      attacker: "Lazarus Group (TraderTraitor targeting vendor Ginco)",
      mitreTags: ["T1566 Recruiter Lure", "T1539 Cookie Theft", "PSBT Parameter Spoof", "Peel Chain / Sinbad"],
      humanFailure: "Recruiter phishing compromised an engineer at custody vendor Ginco -> attackers hijacked session cookies to manipulate legitimate BTC transaction parameters into a single 4,502.9 BTC drain, then laundered funds via peel chains and mixers.",
      interceptionLayer: "Lane 1 Vendor Blast-Radius Cap + Lane 3 Out-of-Band PSBT Allowlist & Single-Sweep Cap",
      autonomyPct: 95,
      autonomyLabel: "95% Autonomous (Hard allowlist + velocity cap blocks single 4,502.9 BTC sweep)",
      modeledOutcome: "Unwhitelisted destination & >5% reserve single-tx cap auto-block drain pre-signature (modeled >98% saved)",
      timeline: [
        { t: "Mar–May 2024", txt: "Historical: TraderTraitor malware on Ginco developer laptop stole session cookies to access unencrypted wallet-management communications.", intercept: false },
        { t: "May 31 · T-0s", txt: "InfiniteSecurity Autonomous Stop: Independent raw-PSBT verifier rejects destination outside immutable Cold/Warm allowlist AND rejects single-tx size > dynamic hot/warm cap (4,502.9 BTC >> 25 BTC automated ceiling).", intercept: true },
        { t: "T + 5s", txt: "Auto-triggers out-of-band board alert + freezes vendor API channel without halting verified small customer withdrawals.", intercept: false }
      ],
      vulnFilename: "custody_bridge/btc_tx_builder.py (Vulnerable Uncapped PSBT Flow)",
      vulnCode: `# Custody vendor server prepares unsigned PSBT / BTC outputs without independent policy lock:
def submit_to_signing_quorum(session_cookie: str, dest_btc_addr: str, amount_btc: float):
    # [ISSUE 1] Hijacked Ginco session cookie lets attacker tamper dest_btc_addr & amount_btc!
    # [ISSUE 2] No immutable destination allowlist verified on raw PSBT output scripts!
    # [ISSUE 3] Zero single-transaction velocity ceiling (4,502.9 BTC passed in ONE sweep!)
    return quorum_hsm.sign_btc_tx(
        outputs=[{"address": dest_btc_addr, "btc": amount_btc}]
    )`,
      safeFilename: "infinitesec_policies/btc_presign_guard.rego (InfiniteSecurity Autonomous Policy)",
      safeCode: `package custody.btc_presign_guard

# Independently parsed from raw unsigned PSBT bytes BEFORE hardware quorum signs (0 keys held):
deny[msg] {
    some out in input.decoded_psbt_outputs
    not immutable_cold_warm_allowlist[out.address]
    msg := sprintf("BLOCK_UNWHITELISTED_BTC_OUTPUT: %v", [out.address])
}

deny[msg] {
    input.total_output_btc > data.limits.max_single_sweep_btc   # e.g., 25 BTC hard ceiling
    not input.board_airgap_fido2_quorum_attestation
    msg := sprintf("BLOCK_EXCESS_SWEEP_VELOCITY: %v BTC > policy ceiling", [input.total_output_btc])
}

deny[msg] {
    input.session_auth_method == "browser_cookie_only"          # Rejects cookie-only sessions!
    msg := "BLOCK_COOKIE_ONLY_CUSTODY_COMMAND"
}`,
      issues: [
        { sev: "CRITICAL", title: "Single Manipulated Transaction Emptied 4,502.9 BTC", detail: "Absence of an independent immutable BTC output allowlist and hard per-transaction cap allowed one spoofed vendor request to drain $305M.", fix: "Out-of-band raw PSBT decoder verifies every output address against immutable Cold/Warm allowlists and enforces hard per-tx BTC ceilings." },
        { sev: "HIGH", title: "Session Cookie Theft at Third-Party Vendor Compromised Custody", detail: "Recruiter phishing on a vendor laptop granted unencrypted access to transaction-coordination sessions.", fix: "Ban cookie-only custody auth; require hardware-bound FIDO2 + independent out-of-band parameter attestation." }
      ],
      mitreKillChain: [
        { tactic: "Initial Access (TA0001)", technique: "T1566 LinkedIn Lure", attackerAction: "Fake recruiter sent TraderTraitor malware to engineer at custody vendor Ginco.", humanBlindSpot: "Third-party vendor endpoint hygiene sits outside exchange SOC visibility.", aiStop: "Layer 1/3 treats every third-party custody vendor as untrusted; enforces exchange-side byte verifier.", latency: "Pre-sign" },
        { tactic: "Credential Access (TA0006)", technique: "T1539 Session Cookie", attackerAction: "Stole valid session cookies to intercept wallet-management coordination.", humanBlindSpot: "Unencrypted session reuse allowed silent parameter modification in transit.", aiStop: "Layer 3 Rego policy rejects cookie-only auth and requires cryptographic hardware attestation.", latency: "< 100 ms" },
        { tactic: "Impact (TA0040)", technique: "4,502.9 BTC Sweep", attackerAction: "Manipulated routine transfer into single 4,502.9 BTC ($305M) drain -> peel chains & Sinbad.", humanBlindSpot: "No hard per-tx BTC ceiling or immutable output script allowlist at signing boundary.", aiStop: "Layer 3 blocks unwhitelisted output & >25 BTC single-tx sweep autonomously before sign.", latency: "< 200 ms" }
      ],
      activeDefense: {
        tier1: "FIDO2 hardware-bound auth + zero cookie-based approval sessions across vendor custody bridges.",
        tier2: "Immutable Cold/Warm destination allowlist enforced on raw decoded PSBT scriptPubKey outputs.",
        tier3: "Hard automated single-tx cap (25 BTC) & hourly velocity cap requiring air-gapped board quorum above ceiling.",
        tier4: "Automatic vendor API circuit breaker quarantines compromised vendor channel in <3s.",
        walletCap: "Cold/Warm segmentation prevents any single vendor-initiated transfer from exceeding intra-day liquidity bounds.",
        reconciliation: "Real-time UTXO balance reconciliation against internal customer BTC liabilities.",
        activeMechanism: "Out-of-band PSBT verification neutralizes third-party vendor breaches even if vendor servers are 100% owned."
      },
      counterfactual: {
        humanMttd: "Single 4,502.9 BTC transaction confirmed on-chain before alert",
        humanLoss: "$305M (4,502.9 BTC; exchange raised emergency capital & wound down)",
        humanTouchpoints: "Vendor engineer + custody parameter approval without OOB check",
        humanUptime: "Service restrictions and ultimate business wind-down",
        aiLatency: "< 150 ms raw PSBT policy rejection",
        aiLoss: "$0 (unwhitelisted address & 4,502.9 BTC cap hard-blocked)",
        aiTouchpoints: "0 human inspection needed to reject oversized unwhitelisted output",
        aiUptime: "100% normal retail BTC withdrawals preserved",
        receiptJson: `{\n  "engine": "InfiniteSecurity BTC PSBT Verifier",\n  "decision": "BLOCK_SIGNING",\n  "reasons": ["BLOCK_UNWHITELISTED_BTC_OUTPUT", "BLOCK_EXCESS_SWEEP_VELOCITY(4502.9_BTC)"],\n  "latency_ms": 94,\n  "unilateral_key_access": "NONE"\n}`
      }
    },
    {
      id: "cryptocom-2022",
      venue: "Crypto.com",
      date: "Jan 17, 2022",
      category: "cloud_logic",
      catLabel: "Backend Withdrawal API 2FA Bypass Logic Flaw",
      color: "var(--c-vault)",
      lossReported: "$35M (4,836.26 ETH + 443.93 BTC · 483 accounts)",
      attacker: "External Threat Actors (Server-Side API Auth Bypass)",
      mitreTags: ["T1190 API Logic Flaw", "T1550 Session Replay", "483 Accounts", "Tornado Cash Exfil"],
      humanFailure: "Backend withdrawal API accepted authenticated login sessions without verifying fresh per-transaction 2FA proofs; detected at 00:46 UTC after 483 accounts were drained, forcing a 14-hour blanket withdrawal freeze and global 2FA reset.",
      interceptionLayer: "Lane 1 Auth-Invariant CI Differential Test + Lane 5 24h Whitelist Lock & `<3s` Burst Breaker",
      autonomyPct: 96,
      autonomyLabel: "96% Autonomous (CI catches missing step-up auth + <3s burst breaker stops 483-account sweep)",
      modeledOutcome: "Caught pre-merge in CI invariant suite; runtime 24h new-address lock + burst breaker stops multi-account drain at <1%",
      timeline: [
        { t: "Pre-Merge CI", txt: "InfiniteSecurity Autonomous Stop #1: API differential replay tests confirm every `/withdraw` endpoint rejects requests missing a fresh (<60s) WebAuthn/TOTP proof bound to `(userId, destAddress, amount)`.", intercept: true },
        { t: "Jan 17 · 00:46 UTC", txt: "Historical: Attackers bypassed 2FA across 483 accounts, draining 4,836.26 ETH + 443.93 BTC (~$35M) to Tornado Cash before a 14-hour exchange-wide withdrawal halt.", intercept: false },
        { t: "T + 2 sec", txt: "InfiniteSecurity Autonomous Stop #2: Mandatory 24h cooldown on newly registered payout addresses + LLR-CUSUM multi-account burst detector auto-isolates anomalous withdrawals without freezing legitimate 2FA users.", intercept: true }
      ],
      vulnFilename: "api/withdrawal_controller.ts (Vulnerable Server-Side Auth Check)",
      vulnCode: `// Vulnerable backend API checks only general login session, skipping fresh step-up 2FA:
app.post("/api/v2/withdraw", requireSessionCookie, async (req, res) => {
  const { userId, destAddress, amount } = req.body;
  // [ISSUE 1] Trusts stale login-time session flag instead of fresh per-tx 2FA proof!
  // [ISSUE 2] No cryptographic binding between 2FA token and (destAddress, amount)!
  // [ISSUE 3] No 24-hour whitelist cooldown on newly registered payout addresses!
  if (req.session.isAuthenticated) {
    return hotWallet.dispatchWithdrawal(userId, destAddress, amount); // 483 accounts drained!
  }
});`,
      safeFilename: "infinitesec_policies/stepup_mfa_and_whitelist.ts (InfiniteSecurity Enforced)",
      safeCode: `// Verified on every PR via InfiniteSecurity Auth-Invariant Replay + enforced at API gateway:
app.post("/api/v2/withdraw", requireSessionCookie, async (req, res) => {
  const { userId, destAddress, amount, webauthnAssertion } = req.body;

  // 1. Cryptographically bind fresh (<60s) FIDO2/TOTP proof to exact (userId, dest, amount, nonce)
  const challengeHash = sha256(\`\${userId}|\${destAddress}|\${amount}|\${req.nonce}\`);
  if (!verifyFreshStepUpAuth(userId, webauthnAssertion, challengeHash, { maxAgeSec: 60 })) {
    return res.status(403).json({ error: "STEPUP_MFA_PROOF_REQUIRED" });
  }

  // 2. Enforce immutable 24-hour whitelist cooldown on newly registered withdrawal addresses
  if (whitelistAgeHours(userId, destAddress) < 24) {
    return res.status(423).json({ error: "NEW_WHITELIST_24H_COOLDOWN_ACTIVE" });
  }

  // 3. Evaluate cross-account LLR-CUSUM burst detector (stops 483-account wave at account #3)
  return hotWallet.dispatchScopedWithdrawal(userId, destAddress, amount);
});`,
      issues: [
        { sev: "CRITICAL", title: "Session-Level 2FA Reuse Bypasses Per-Withdrawal Confirmation", detail: "2FA is not a silver bullet if server-side API code accepts cached login flags instead of verifying fresh per-transaction proofs.", fix: "CI auth-invariant replay tests fail any PR missing per-tx cryptographic step-up verification bound to `(dest, amount)`." },
        { sev: "HIGH", title: "14-Hour Blanket Freeze Penalizes 100% of Honest Customers", detail: "Manual incident response had to shut down withdrawals globally for 14 hours and force every user to reset 2FA.", fix: "Mandatory 24h new-address lock + scoped LLR-CUSUM quarantines anomalous sessions in <3s while keeping legitimate withdrawals live." }
      ],
      mitreKillChain: [
        { tactic: "Initial Access (TA0001)", technique: "T1190 API Logic Bug", attackerAction: "Discovered backend withdrawal API accepted session tokens without fresh 2FA re-verification.", humanBlindSpot: "Unit tests checked happy-path withdrawals, not negative auth-bypass differential replays.", aiStop: "Layer 1 CI runs negative auth-bypass fuzzing on every `/withdraw` route PR.", latency: "< 45s (CI)" },
        { tactic: "Privilege Abuse", technique: "T1550 Session Replay", attackerAction: "Spoofed approved authentication parameters across 483 user accounts.", humanBlindSpot: "No device/IP cross-check or 24h cooldown on newly added payout addresses.", aiStop: "Layer 5 enforces 24h new-address lock + cryptographic binding `(user, dest, amount)`.", latency: "< 50 ms" },
        { tactic: "Exfiltration (TA0010)", technique: "483-Account Sweep", attackerAction: "Drained 4,836.26 ETH + 443.93 BTC (~$35M) to Tornado Cash before 00:46 UTC halt.", humanBlindSpot: "Manual response halted entire exchange for 14 hours after funds already left.", aiStop: "Layer 5 LLR-CUSUM detects cross-account anomalous spike in <3s -> scoped session revocation.", latency: "< 3 sec" }
      ],
      activeDefense: {
        tier1: "Short-lived (10–15m) risk-scored session tokens + device/IP/geo binding; SMS OTP banned for fund movement.",
        tier2: "Fresh (<60s) FIDO2/Passkey or TOTP proof cryptographically bound to exact `(destAddress, amount)`.",
        tier3: "Immutable 24-hour cooldown on newly added withdrawal addresses creates deterministic reaction window.",
        tier4: "Cross-account LLR-CUSUM burst detector auto-blocks anomalous waves without triggering 14h global freezes.",
        walletCap: "Per-account and global per-minute hot withdrawal rate caps enforced automatically.",
        reconciliation: "Real-time withdrawal audit log verifies every hot-wallet dispatch matches a fresh signed step-up proof.",
        activeMechanism: "Eliminates both API auth regressions pre-merge and 14-hour blanket shutdowns during live anomalies."
      },
      counterfactual: {
        humanMttd: "Detected at 00:46 UTC -> 14-hour global withdrawal freeze",
        humanLoss: "$35M (4,836.26 ETH + 443.93 BTC across 483 accounts)",
        humanTouchpoints: "Manual SOC halt + global 2FA reset across all users",
        humanUptime: "0% withdrawals for 14 hours",
        aiLatency: "Pre-merge CI block (<45s) + <3s runtime burst cutoff",
        aiLoss: "$0 pre-merge; <$300K (<1%) runtime-only burst cap",
        aiTouchpoints: "0 human intervention to isolate anomalous sessions",
        aiUptime: "100% verified 2FA users stay live (no 14h freeze)",
        receiptJson: `{\n  "engine": "InfiniteSecurity Auth-Invariant & Burst Guard",\n  "decision": "RESTRICT_PR_MISSING_STEPUP_BINDING",\n  "endpoint": "POST /api/v2/withdraw",\n  "new_address_cooldown_h": 24,\n  "unilateral_key_access": "NONE"\n}`
      }
    },
    {
      id: "binance-bridge-2022",
      venue: "Binance Bridge (BSC Token Hub)",
      date: "Oct 6, 2022",
      category: "cloud_logic",
      catLabel: "Smart-Contract Cross-Chain Proof Logic Flaw",
      color: "var(--c-code)",
      lossReported: "$570M minted (~$100–137M bridged out before chain halt)",
      attacker: "External Exploiter (IAVL Merkle Proof Forgery)",
      mitreTags: ["IAVL Merkle Forgery", "Block 110217401", "2M Unbacked BNB", "Chain-Wide Halt"],
      humanFailure: "Subtle IAVL Merkle proof verification bug in BSC Token Hub allowed forged proofs at historical block `110217401` to mint 2,000,000 unbacked BNB in 2 transactions; required emergency manual validator coordination to halt the entire BNB Smart Chain.",
      interceptionLayer: "Lane 1 Tier-4 Differential Proof Fuzzer + Lane 5 On-Chain Supply Conservation Circuit Breaker",
      autonomyPct: 92,
      autonomyLabel: "92% Autonomous (On-chain lockbox invariant reverts unbacked mint in same block)",
      modeledOutcome: "Unbacked mint reverts atomically on-chain (`mint <= verified_lockbox_delta`) without halting the whole L1 chain",
      timeline: [
        { t: "Pre-Deploy CI", txt: "InfiniteSecurity Autonomous Stop #1: Tier-4 differential fuzz & AST invariant suite tests malformed/extra-leaf IAVL proof structures against reference verifiers before bridge deployment.", intercept: true },
        { t: "Oct 6 · Block N", txt: "Historical: Attacker submitted crafted IAVL proof referencing historical block `110217401` to mint 2,000,000 unbacked BNB (~$570M) in two transactions.", intercept: false },
        { t: "Same Block · T-0s", txt: "InfiniteSecurity Autonomous Stop #2: On-chain Bridge Supply-Conservation Circuit Breaker (`net_mint_24h <= verified_source_lockbox_cap`) reverts the forged 1M BNB mint atomically — no whole-chain shutdown needed.", intercept: true }
      ],
      vulnFilename: "contracts/BSCTokenHub_IAVL.sol (Vulnerable Proof & Unbounded Mint)",
      vulnCode: `// Vulnerable cross-chain bridge accepts unvalidated inner IAVL leaf/right-branch payload
// AND imposes ZERO per-window supply-conservation cap on minted wrapped tokens:
function handlePackage(bytes calldata payload, bytes calldata proof, uint64 height) external {
    // [ISSUE 1] Subtle inner-node parsing bug lets attacker append extra forged leaf at height 110217401!
    require(verifyIAVLMerkleProof(payload, proof, height), "INVALID_PROOF");

    // [ISSUE 2] Mints 1,000,000 BNB directly with zero per-tx cap, zero rolling window limit,
    //           and zero check against verified source-chain lockbox deposit delta!
    _mintUnbounded(decoded.recipient, decoded.amount);
}`,
      safeFilename: "contracts/InfiniteSecBridgeSupplyGuard.sol (Autonomous On-Chain Invariant)",
      safeCode: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Deterministic on-chain defense-in-depth invariant (reverts forged mint in same block):
contract InfiniteSecBridgeSupplyGuard {
    uint256 public immutable MAX_SINGLE_RELEASE_CAP;
    uint256 public immutable WINDOW_OUTFLOW_CAP;

    function checkAndRelease(
        bytes32 proofDigest,
        uint256 amount,
        uint256 verifiedLockboxReserve
    ) external {
        require(!consumedProofs[proofDigest], "REPLAY_BLOCKED");
        require(amount <= MAX_SINGLE_RELEASE_CAP, "EXCEEDS_SINGLE_TX_CIRCUIT_BREAKER");
        require(windowOutflow + amount <= WINDOW_OUTFLOW_CAP, "WINDOW_VELOCITY_CIRCUIT_BREAKER");

        // Hard conservation invariant: bridge can NEVER release more than verified lockbox delta
        require(totalReleased + amount <= verifiedLockboxReserve, "CONSERVATION_INVARIANT_BREACH");

        consumedProofs[proofDigest] = true;
        windowOutflow += amount;
        totalReleased += amount;
    }
}`,
      issues: [
        { sev: "CRITICAL", title: "Zero Conservation Invariant on Cross-Chain Minting", detail: "When a subtle Merkle proof parser bug exists, an unbounded mint function lets two transactions create $570M out of thin air.", fix: "Combine Tier-4 differential proof fuzzing in CI with deterministic on-chain outflow velocity & lockbox conservation circuit breakers." },
        { sev: "HIGH", title: "Manual Validator Coordination Required Whole-Chain Shutdown", detail: "Containing the exploit forced human operators to coordinate validators to pause the entire L1 blockchain.", fix: "Autonomous per-bridge circuit breaker reverts the offending mint atomically inside the same block with 0 L1 downtime." }
      ],
      mitreKillChain: [
        { tactic: "Discovery / Exploit", technique: "IAVL Proof Edge Case", attackerAction: "Crafted extra-leaf IAVL proof against historical block height `110217401`.", humanBlindSpot: "Manual smart-contract audit missed subtle non-canonical inner-branch proof acceptance.", aiStop: "Layer 1 differential fuzzer cross-checks canonical vs. malformed proof encodings in CI.", latency: "Pre-deploy CI" },
        { tactic: "Impact (TA0040)", technique: "2M BNB Unbacked Mint", attackerAction: "Minted 2,000,000 BNB ($570M) in 2 txs and began bridging ~$100–137M cross-chain.", humanBlindSpot: "No on-chain single-tx cap or lockbox conservation check stopped a 1M BNB mint.", aiStop: "Layer 5 on-chain `InfiniteSecBridgeSupplyGuard` reverts tx atomically inside same block.", latency: "0 sec (Atomic)" }
      ],
      activeDefense: {
        tier1: "Tier-4 differential proof fuzzing & symbolic AST invariants on every bridge contract PR.",
        tier2: "Canonical proof strictness checks forbid trailing/extra inner branches.",
        tier3: "On-chain `MAX_SINGLE_RELEASE_CAP` and rolling 24h `WINDOW_OUTFLOW_CAP` enforced inside contract bytecode.",
        tier4: "Hard supply-conservation invariant (`totalReleased <= verifiedLockboxReserve`) + dual-verifier quorum.",
        walletCap: "Bridge mint/release authority capped strictly to verified lockbox deposit delta.",
        reconciliation: "Continuous cross-chain lockbox-vs-wrapped-supply proof reconciliation.",
        activeMechanism: "Atomic on-chain revert halts forged mints instantaneously without pausing the underlying L1 chain."
      },
      counterfactual: {
        humanMttd: "Manual validator war-room coordination to halt entire BSC chain",
        humanLoss: "$570M minted (~$100–137M bridged out before chain pause)",
        humanTouchpoints: "Emergency multi-validator manual chain shutdown",
        humanUptime: "Entire L1 blockchain halted during emergency patch",
        aiLatency: "0 ms (same-block atomic EVM revert)",
        aiLoss: "$0 unbacked BNB minted",
        aiTouchpoints: "0 human intervention required to revert forged proof",
        aiUptime: "100% L1 blockchain uptime preserved",
        receiptJson: `{\n  "engine": "InfiniteSecurity On-Chain Bridge Guard",\n  "decision": "REVERT_ATOMIC",\n  "reason": "EXCEEDS_SINGLE_TX_CIRCUIT_BREAKER + CONSERVATION_INVARIANT_BREACH",\n  "attempted_mint_bnb": 1000000,\n  "l1_chain_halted": false\n}`
      }
    },
    {
      id: "wave-2025-2026",
      venue: "2025–2026 Vendor, APT & Cross-Chain Wave (SwissBorg, CoinDCX, Phemex, BtcTurk, Nobitex, Drift, KelpDAO)",
      date: "Jan 2025 – Apr 2026",
      category: "oss_supply",
      catLabel: "Third-Party APIs, Signer Grooming, Single-Verifier Bridges & Geopolitical Burn",
      color: "var(--c-sla)",
      lossReported: "$885M+ combined ($292M KelpDAO, $285M Drift, $90M Nobitex burn, $85M Phemex, $48M BtcTurk, $44.2M CoinDCX, $41M SwissBorg)",
      attacker: "DPRK APT (~76% of H1 2026 stolen value) + Predatory Sparrow (Nobitex)",
      mitreTags: ["T1199 Partner API (Kiln)", "Single-DVN Bridge", "12-Min Signer Sweep", "Geopolitical Burn"],
      humanFailure: "SwissBorg ($41M): compromised staking partner Kiln API. CoinDCX ($44.2M): internal liquidity server breach. Phemex ($85M) & BtcTurk ($48M repeat): hot-wallet key compromises. Nobitex ($90M): geopolitical attack permanently burning funds to unspendable vanity addresses. Drift ($285M): months of signer social engineering -> 12-min drain. KelpDAO ($292M): single-verifier LayerZero bridge design + THORChain laundering.",
      interceptionLayer: "Lane 1 Single-Verifier & Vendor Graph Lint + Lane 3 OOB Quorum + `<3s` Autonomous Velocity Kill-Switch",
      autonomyPct: 94,
      autonomyLabel: "94% Autonomous (Eliminates single-verifier bridges & caps 12-min signer/partner sweeps)",
      modeledOutcome: "Catches single-verifier bridge config in CI (KelpDAO); 24h timelock + treasury-pinned partner APIs + <3s caps halt rapid sweeps",
      timeline: [
        { t: "CI Policy Lint", txt: "InfiniteSecurity Autonomous Stop #1 (KelpDAO $292M): Graph & contract linter flags `requiredDVNCount == 1` (single-verifier LayerZero bridge) as `RESTRICT` pre-deploy — mandating >=2 independent verifier organizations.", intercept: true },
        { t: "Vendor API Seam", txt: "InfiniteSecurity Autonomous Stop #2 (SwissBorg/Kiln $41M & CoinDCX $44.2M): Partner staking APIs & internal liquidity servers are fenced with hard daily transfer caps & immutable return-to-treasury-only destination lists.", intercept: true },
        { t: "12-Min / Burn Sweeps", txt: "InfiniteSecurity Autonomous Stop #3 (Drift $285M, Phemex $85M, BtcTurk $48M, Nobitex $90M): 24h timelock on signer/threshold rotations + immutable destination allowlists (blocking unspendable burn addresses!) + `<3s` burst breaker turn 12-minute sweeps into halted zero-loss attempts.", intercept: true }
      ],
      vulnFilename: "bridge_and_vendor/config.yaml (Vulnerable 2025–2026 Patterns)",
      vulnCode: `# 1. Single-verifier cross-chain bridge (KelpDAO $292M Apr 2026 pattern):
layerzero_uln_config:
  required_dvn_count: 1             # [ISSUE 1] Single compromised DVN drains $292M -> THORChain!

# 2. Uncapped third-party staking partner API (SwissBorg / Kiln $41M pattern):
partner_api_kiln:
  allowed_withdraw_destinations: "*"  # [ISSUE 2] Partner API breach redirects $41M SOL!
  max_hourly_sweep_usd: UNLIMITED

# 3. Zero-delay admin quorum rotation & unallowlisted destinations (Drift 12m / Nobitex burn):
multisig_admin_change_timelock_hours: 0   # [ISSUE 3] Social-engineered signers drain in 12 mins!
allow_arbitrary_destination_address: true # [ISSUE 4] Permits irreversible geopolitical burn addresses!`,
      safeFilename: "infinitesec_policies/vendor_bridge_quorum.yaml (InfiniteSecurity Enforced)",
      safeCode: `# Enforced automatically on every PR & runtime seam by InfiniteSecurity Digital Twin:
layerzero_uln_config:
  required_dvn_count: 2             # [FIXED] Minimum 2 independent verifier orgs required
  min_block_confirmations: 20

partner_api_kiln:
  # Hard-pinned to exchange's own immutable treasury return address ONLY (0 external payouts):
  allowed_withdraw_destinations: ["0x2222222222222222222222222222222222222222"]
  max_hourly_sweep_usd: 2000000
  auto_circuit_breaker_on_anomaly: true  # <3s autonomous pause

custody_quorum_governance:
  multisig_admin_change_timelock_hours: 24  # Neutralizes 12-minute social-engineered sweeps!
  require_immutable_destination_allowlist: true  # Blocks irreversible burn-address destruction!
  hot_wallet_max_float_pct: 5               # Caps Phemex / BtcTurk hot blast radius`,
      issues: [
        { sev: "CRITICAL", title: "Single-Verifier Bridges & Uncapped Partner APIs Dominated 2025–2026", detail: "One compromised bridge verifier (KelpDAO $292M) or staking partner API (SwissBorg/Kiln $41M) drained hundreds of millions without touching core exchange wallets.", fix: "CI twin mandates >=2 independent bridge verifiers and pins partner APIs strictly to immutable treasury return addresses." },
        { sev: "CRITICAL", title: "12-Minute Signer Drains & Irreversible Geopolitical Burn Attacks", detail: "Drift signers were groomed for months then drained in 12 minutes ($285M); Nobitex lost $90M permanently to unspendable geopolitical burn addresses.", fix: "Mandatory 24h admin-change timelocks, immutable payout allowlists (rejecting burn addresses), and `<3s` outflow circuit breakers." }
      ],
      mitreKillChain: [
        { tactic: "Bridge Misconfig", technique: "Single-DVN Quorum", attackerAction: "KelpDAO (Apr 18, 2026): TraderTraitor exploited single-verifier LayerZero config for $292M -> THORChain.", humanBlindSpot: "Bridge DVN threshold was a single YAML/constructor parameter missed in review.", aiStop: "Layer 1 CI bridge linter rejects `requiredDVNCount < 2` automatically pre-deploy.", latency: "< 45s (CI)" },
        { tactic: "Trusted Partner API", technique: "T1199 Staking API", attackerAction: "SwissBorg (Sep 2025): Compromised Kiln partner API redirected $41M SOL; CoinDCX ($44.2M) internal server pivot.", humanBlindSpot: "Partner staking API could sweep to arbitrary unpinned external wallets.", aiStop: "Layer 3 pins partner APIs strictly to immutable exchange-owned treasury return addresses.", latency: "< 100 ms" },
        { tactic: "Social Engineering", technique: "12-Min Quorum Sweep", attackerAction: "Drift (Apr 1, 2026): Months of signer grooming + 3 weeks staging -> 12-min $285M sweep.", humanBlindSpot: "Zero timelock on admin/quorum changes left 0 minutes for detection.", aiStop: "Layer 3/5 enforces 24h timelock on threshold/signer mutations + <3s velocity kill-switch.", latency: "24h lock / <3s" },
        { tactic: "Geopolitical Burn", technique: "Irreversible Vanity Burn", attackerAction: "Nobitex (Jun 2025): Predatory Sparrow sent ~$90M to unspendable vanity burn addresses (0% recovery possible).", humanBlindSpot: "Post-facto tracing/freezing cannot recover funds sent to provably unspendable burn addresses.", aiStop: "Layer 3 immutable destination allowlists + hot caps (<5%) prevent unauthorized transfers pre-broadcast.", latency: "< 200 ms" }
      ],
      activeDefense: {
        tier1: "Anti-deepfake callback codes + FIDO2 + mandatory 24h timelock on signer/policy changes (stops Drift/Lazarus grooming).",
        tier2: "Partner APIs & internal liquidity servers restricted strictly to immutable treasury return addresses (stops SwissBorg/CoinDCX).",
        tier3: "CI bridge-config linter forbids single-verifier cross-chain bridges (`requiredDVNCount >= 2`, stops KelpDAO).",
        tier4: "Strict <5% hot caps + immutable allowlists prevent repeat hot drains (BtcTurk/Phemex) and permanent burn destruction (Nobitex).",
        walletCap: "Hot <5% per chain, Partner API return-only, Bridge multi-DVN + 24h mint caps.",
        reconciliation: "Continuous cross-chain & partner-API balance attestation against internal treasury ledger.",
        activeMechanism: "Eliminates single points of failure across partner vendors, bridges, and social-engineered signers simultaneously."
      },
      counterfactual: {
        humanMttd: "12-min drain (Drift), single-block bridge exploit (KelpDAO), unrecoverable burn (Nobitex)",
        humanLoss: "$885M+ combined across 7 incidents (DPRK = 76% of H1 2026 losses)",
        humanTouchpoints: "Manual vendor trust, unlinted bridge params, social-engineered human signers",
        humanUptime: "Emergency pauses, reserve drawdowns, irreversible burn losses",
        aiLatency: "< 45s CI bridge lint / < 200ms destination lock / < 3s burst cutoff",
        aiLoss: "Modeled >95% prevented across all 7 incident vectors",
        aiTouchpoints: "0 human intervention to enforce DVN quorum, return-only APIs, or 24h timelocks",
        aiUptime: "100% verified retail withdrawals remain online",
        receiptJson: `{\n  "engine": "InfiniteSecurity Vendor & Bridge Policy Twin",\n  "decision": "RESTRICT_AND_ENFORCE_QUORUM",\n  "rules_enforced": ["MIN_BRIDGE_DVN>=2", "PARTNER_API_RETURN_ONLY", "ADMIN_TIMELOCK_24H", "BURN_ADDR_BLOCKED"],\n  "unilateral_key_access": "NONE"\n}`
      }
    }
  ];

  // ==================== 2. INTERACTIVE LOSS-CONTAINMENT SIMULATOR DATA ====================
  const SIM_SCENARIOS = {
    upbit_solana: {
      name: "Upbit Solana 400ms Nonce-Bias Drain",
      maxLossM: 37.0,
      drainDurationMin: 54,
      mode: "linear",
      humanTouchpoints: 11,
      humanFreezeLabel: "0% (Full Solana freeze during cold sweep)",
      premergeStops: true,
      oobStops: false,
      cryptoStops: true,
      breakerCapM: 0.65,
      summary: "At 400ms Solana block speeds, a 30-minute human SOC reaction loses ~$20.6M before a manual pause lands. InfiniteSecurity blocks biased Ed25519 crates pre-deploy ($0) or trips its <3s LLR-CUSUM entropy breaker (<$0.65M max)."
    },
    bybit_cold: {
      name: "Bybit / WazirX S3 UI Tamper + Blind Sign",
      maxLossM: 1500.0,
      drainDurationMin: 2,
      mode: "atomic",
      humanTouchpoints: 9,
      humanFreezeLabel: "Emergency multi-billion bridge liquidity required",
      premergeStops: true,
      oobStops: true,
      cryptoStops: false,
      breakerCapM: 75.0,
      summary: "Atomic Safe `slot[0]` proxy takeover drains $1.5B in 1 transaction (JS wiped 2 minutes later), so even a 5-minute human SOC is 100% too late. InfiniteSecurity's <200ms Out-of-Band `debug_traceCall` verifier hard-blocks signing pre-tap ($0 lost)."
    },
    bitget_vendor: {
      name: "Bitget / Binance Internal Signing & Vendor Command Injection",
      maxLossM: 387.5,
      drainDurationMin: 18,
      mode: "linear",
      humanTouchpoints: 14,
      humanFreezeLabel: "0% (Multi-chain withdrawal suspension)",
      premergeStops: true,
      oobStops: true,
      cryptoStops: false,
      breakerCapM: 4.2,
      summary: "Forged withdrawal commands across 11 chains outrun human SIEM correlation in under 20 minutes. InfiniteSecurity's HSM-boundary User-Ledger Merkle proof & EIP-7702 `0x04` guard reject forged commands in <200ms ($0 lost)."
    },
    mixin_cloud: {
      name: "Mixin / CoinDCX Cloud DB & PyYAML Workstation Pivot",
      maxLossM: 200.0,
      drainDurationMin: 15,
      mode: "linear",
      humanTouchpoints: 12,
      humanFreezeLabel: "0% (Kernel frozen; 50% user haircut)",
      premergeStops: true,
      oobStops: false,
      cryptoStops: false,
      breakerCapM: 1.0,
      summary: "Once Cloud DB and static GCS JS are tampered, automated MPC drains $200M inside 15 minutes. InfiniteSecurity's Zero-Direct-Access CI/CD stops GCS/DB writes pre-deploy, and continuous T+0 Ledger-vs-Chain reconciliation halts at the first $1M delta (>99% saved)."
    },
    cryptocom_api: {
      name: "Crypto.com / Drift API Auth Bypass & Quorum Sweep",
      maxLossM: 285.0,
      drainDurationMin: 12,
      mode: "linear",
      humanTouchpoints: 10,
      humanFreezeLabel: "0% (14-hour blanket exchange freeze)",
      premergeStops: true,
      oobStops: true,
      cryptoStops: false,
      breakerCapM: 1.8,
      summary: "Drift's $285M sweep finished in 12 minutes; Crypto.com's 483-account API bypass forced a 14-hour global freeze. InfiniteSecurity's CI auth-invariant tests + 24h timelocks + <3s burst breaker contain loss to $0–$1.8M while keeping 12/12 honest user flows live."
    }
  };

  // ==================== 3. COMPLETE 32-INCIDENT EMPIRICAL REFERENCE LEDGER (2011–2026) ====================
  const EMPIRICAL_LEDGER = [
    ["Mt. Gox", "2011–14", "850,000 BTC", "Hot wallet vulnerability & loose governance", "Early Infrastructure", "Partial court refund", "Layer 5: T+0 Ledger Reconciliation + Triple-Layer Caps"],
    ["Bitstamp", "2015", "$5M", "Staff phishing malware targeting hot wallet", "Social Engineering", "Self-compensated", "Layer 2: Hardened CI/CD + StateFence + Hot <5% Cap"],
    ["Bitfinex", "2016", "119,756 BTC", "Multi-signature withdrawal protocol flaw (BitGo)", "Protocol / Signing Seam", "BFX debt tokens repaid", "Layer 3: Independent OOB Verifier + Velocity Quorum"],
    ["Coincheck", "2018", "$534M", "523M NEM held in hot wallet without multi-sig", "Hot Wallet Exposure", "100% self-refunded", "Layer 5: Triple-Layer Wallet (Hot <5%, Cold >90%)"],
    ["BitGrail", "2018", "$170M", "Duplicate withdrawal race-condition bug (Nano)", "Software / API Logic", "Bankruptcy litigation", "Layer 1/5: Idempotency Invariants + T+0 Conservation"],
    ["Coinrail & Zaif", "2018", "$100M combined", "ERC-20 & hot-wallet signing infrastructure flaws", "Hot Wallet / Signing", "Partial freeze / buyout", "Layer 3/5: Out-of-Band Policy + <3s Burst Breaker"],
    ["Coinsecure", "2018", "$3.3M", "Suspected insider CSO key compromise", "Insider Threat", "Personal restitution", "Layer 3: Strict SoD + M-of-N Hardware Quorum"],
    ["Binance (2019)", "2019", "$40M (7,000 BTC)", "Multi-vector phishing, API keys & 2FA theft", "Multi-Layer Phishing", "100% covered by SAFU", "Layer 3/5: Per-Tx Step-Up Binding + <3s Burst Cap"],
    ["Upbit (2019)", "2019", "$50M (342,000 ETH)", "ETH hot-wallet private key leak (Lazarus)", "State APT (DPRK)", "100% reserve-reimbursed", "Layer 4/5: HSM/MPC + Hot <5% Cap + T+0 Kill-Switch"],
    ["Cryptopia", "2019", "$16–30M", "Pooled hot-wallet server compromise", "Infrastructure Breach", "Court liquidation", "Layer 5: Segregated Key Tiers + Automated Safe Mode"],
    ["KuCoin", "2020", "$281M", "Hot-wallet private key leak across chains", "Infrastructure Breach", "84% on-chain recovery", "Layer 5: Hot Cap (<5%) + <3s Multi-Chain Breaker"],
    ["EXMO", "2020", "$10.5M", "Wallet management server intrusion (fast halt)", "Hot Wallet Server", "100% user-reimbursed", "Layer 5: Autonomous <3s Breaker (beats manual halt)"],
    ["Liquid", "2021", "$90M", "DNS / warm-wallet supply-chain compromise", "Supply Chain", "Emergency credit line", "Layer 2/3: Static Integrity Lock + OOB Allowlists"],
    ["BitMart", "2021", "$196M", "Stolen admin keys draining ETH & BSC hot wallets", "Hot Wallet Key Theft", "Compensated from funds", "Layer 3/5: Ledger Merkle Proof + Per-Minute Outflow Cap"],
    ["AscendEX", "2021", "$77M", "Cloud-hosted hot-wallet server compromise", "Cloud Infrastructure", "100% self-compensated", "Layer 1/2: Zero-Direct-Access Cloud IAM BFS"],
    ["Crypto.com", "2022", "$35M", "Backend withdrawal API 2FA bypass (483 accts)", "Auth Logic Flaw", "100% reimbursed (14h halt)", "Layer 1/5: CI Auth Invariants + 24h Lock + <3s Breaker"],
    ["Binance Bridge", "2022", "$570M minted", "IAVL Merkle proof verification bug (2M BNB)", "Smart Contract Bridge", "Chain halted (~$100-137M out)", "Layer 1/5: Diff Proof Fuzzing + On-Chain Supply Guard"],
    ["FTX", "2022", "$477M", "Loose key governance & unsegregated controls", "Governance / Insider", "Complex bankruptcy", "Layer 3/5: Hardware M-of-N + Continuous Proof-of-Reserve"],
    ["Mixin Network", "2023", "$200M", "PyYAML RCE -> GCP Cloud DB & GCS JS tamper", "Web2 Supply Chain (DPRK)", "50% haircut / debt plan", "Layer 1/2/5: Zero-Direct CI/CD + Static SRI + T+0 Safe Mode"],
    ["Poloniex", "2023", "$126M", "APT hot-wallet private key compromise (Lazarus)", "State APT (DPRK)", "Reserve restitution", "Layer 4/5: FROST MPC + MTD Resharing + <3s Velocity Cap"],
    ["HTX & Heco", "2023", "$110M", "Hot-wallet & cross-chain bridge key leak", "Key & Bridge Seam", "100% user-reimbursed", "Layer 3/5: Multi-Verifier Bridge + Hot Caps"],
    ["Bitrue", "2023", "$23M", "Hot-wallet vulnerability across ERC-20 tokens", "Hot Wallet Exploit", "Insurance fund covered", "Layer 5: Per-Token Outflow Caps + LLR-CUSUM"],
    ["DMM Bitcoin", "2024", "$305M (4,502.9 BTC)", "Vendor (Ginco) cookie theft -> spoofed BTC tx", "Supply Chain APT (DPRK)", "Capital raise / wind-down", "Layer 3: OOB Raw PSBT Allowlist + Single-Tx BTC Cap"],
    ["WazirX", "2024", "$230M (~45%)", "Liminal custody UI tamper -> Safe proxy upgrade", "Blind Signing (DPRK)", "Legal restructuring", "Layer 3: 10-Word Safe ABI + `slot[0]` Storage Verifier"],
    ["Phemex", "2025", "$85M", "Multi-chain hot-wallet key compromise", "State APT (DPRK)", "Compensated from reserves", "Layer 4/5: Segregated Chain Keys + <3s Multi-Chain Cap"],
    ["Bybit", "2025", "$1.4B–$1.5B", "Safe{Wallet} PyYAML -> S3 `_app.js` -> blind sign", "Supply Chain APT (DPRK)", "Maintained solvency", "Layer 1/2/3: SBOM + S3 WORM/SRI + OOB `debug_traceCall`"],
    ["Nobitex", "2025", "~$90M", "Internal breach -> funds sent to unspendable burn addr", "Geopolitical Destruction", "Unrecoverable (burned)", "Layer 3/5: Immutable Destination Allowlist + Hot <5%"],
    ["CoinDCX", "2025", "$44.2M", "Server-side breach of internal liquidity account", "Web2 Server Breach", "Treasury covered", "Layer 1/3: Zero-Direct IAM BFS + Treasury-Pinned Payouts"],
    ["BtcTurk", "2025", "~$48M", "Repeat hot-wallet intrusion (after 2024 incident)", "Repeat Hot Wallet", "Reserve-rebalanced", "Layer 4/5: MTD Key Rotation + Automated <3s Circuit Breaker"],
    ["SwissBorg", "2025", "$41M", "Compromised third-party staking partner API (Kiln)", "Partner API Supply Chain", "Compensated users", "Layer 3: Partner APIs Pinned to Immutable Treasury Return"],
    ["Upbit (2025)", "Nov 2025", "~$30–37M (44.5B KRW)", "Randomized Ed25519 MPC LSB nonce bias -> LLL key theft", "Crypto Library / APT", "100% Dunamu compensated", "Layer 1/4/5: FROST + ZKP Nonce + Self-LLL + MTD + <3s Cap"],
    ["Drift & KelpDAO", "Apr 2026", "$577M combined", "Signer grooming (12m drain) & 1-DVN LayerZero bridge", "DPRK (76% of H1 2026)", "Partial freeze / ongoing", "Layer 1/3/5: `DVN>=2` CI Lint + 24h Timelock + <3s Cap"],
    ["Bitget (2026)", "Sep 2026", "~$387.5M", "3rd-party security vendor flaw -> forged 11-chain cmds", "Vendor Supply Chain", "Exchange response", "Layer 2/3/5: Vendor Isolation + Ledger Proof + <3s Cap"],
    ["Binance (2026)", "Oct 2026", "~$6.3B gross", "Dev-tool pivot -> signing service + EIP-7702 `0x04`", "Supply Chain / Signing", "Multi-B frozen", "Layer 1/3/5: SBOM Lock + EIP-7702 Ban + Ledger Merkle Proof"]
  ];

  // ==================== 4. UTILITIES ====================
  function esc(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function escCode(str) {
    return esc(str).replace(/`([^`]+)`/g, "<code>$1</code>");
  }

  function fmtUsdM(m) {
    if (m <= 0.001) return "$0";
    if (m >= 1000) return "$" + (m / 1000).toFixed(2) + "B";
    if (m >= 10) return "$" + m.toFixed(1) + "M";
    return "$" + m.toFixed(2) + "M";
  }

  // ==================== 5. COPY BUTTONS + THEME + ACCORDION + DIALOG FALLBACKS ====================
  function initCopyButtons() {
    const timers = new WeakMap();
    function report(button, ok) {
      const tip = button.nextElementSibling;
      clearTimeout(timers.get(button));
      button.removeAttribute("data-copied");
      button.removeAttribute("data-failed");
      void button.offsetWidth;
      button.setAttribute(ok ? "data-copied" : "data-failed", "");
      if (tip) tip.textContent = ok ? "Copied" : "Copy failed";
      timers.set(button, setTimeout(() => {
        button.removeAttribute("data-copied");
        button.removeAttribute("data-failed");
        if (tip) tip.textContent = "";
      }, 2000));
    }

    async function copyTarget(button, target) {
      if (!target) return;
      const text = (target.textContent || "").trim();
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        report(button, true);
      } catch (_) {
        const ta = Object.assign(document.createElement("textarea"), { value: text });
        ta.style.cssText = "position:fixed;inset-block-start:0;opacity:0";
        document.body.append(ta);
        ta.select();
        const ok = document.execCommand("copy");
        ta.remove();
        report(button, ok);
      }
    }

    if ("CommandEvent" in window) {
      document.addEventListener("command", (event) => {
        if (event.command && event.command.startsWith("--copy")) copyTarget(event.source, event.target);
      }, true);
    } else {
      document.addEventListener("click", (event) => {
        const button = event.target.closest('button[command^="--copy"]');
        if (!button) return;
        const target = document.getElementById(button.getAttribute("commandfor"));
        if (target) copyTarget(button, target);
      });
    }
  }

  function initAccordionToggleAll() {
    function runToggleAll(button, container) {
      if (!button || !container) return;
      const expand = button.getAttribute("aria-expanded") !== "true";
      container.querySelectorAll(":scope > details").forEach((d) => { d.open = expand; });
      button.setAttribute("aria-expanded", String(expand));
    }

    if ("CommandEvent" in window) {
      document.addEventListener("command", (event) => {
        if (event.command !== "--toggle-all") return;
        runToggleAll(event.source, event.target);
      }, { capture: true });
    } else {
      document.addEventListener("click", (event) => {
        const btn = event.target.closest('button[command="--toggle-all"]');
        if (!btn) return;
        const container = document.getElementById(btn.getAttribute("commandfor"));
        runToggleAll(btn, container);
      });
    }

    document.addEventListener("toggle", (event) => {
      if (!event.target.matches(".accordion > details")) return;
      const accordion = event.target.parentElement;
      const btn = accordion.querySelector('[command="--toggle-all"]');
      if (!btn) return;
      const items = accordion.querySelectorAll(":scope > details");
      btn.setAttribute("aria-expanded", String(Array.prototype.every.call(items, (d) => d.open)));
    }, { capture: true });
  }

  function initThemeAndDialogFallbacks() {
    const meta = document.querySelector('meta[name="color-scheme"]');
    const btn = document.getElementById("theme-toggle-btn");
    const lbl = document.getElementById("theme-toggle-label");
    const mql = window.matchMedia("(prefers-color-scheme: dark)");

    function sysScheme() { return mql.matches ? "dark" : "light"; }
    function curScheme() {
      const c = meta ? meta.content.trim() : "light dark";
      return (c === "dark" || c === "light") ? c : sysScheme();
    }
    function syncUI() {
      const r = curScheme();
      document.documentElement.dataset.theme = r;
      if (lbl) lbl.textContent = r === "dark" ? "Light theme" : "Dark theme";
    }
    syncUI();

    if (btn) {
      btn.addEventListener("click", () => {
        const target = curScheme() === "dark" ? "light" : "dark";
        try {
          if (target === sysScheme()) {
            localStorage.removeItem("color-scheme");
            if (meta) meta.content = "light dark";
          } else {
            localStorage.setItem("color-scheme", target);
            if (meta) meta.content = target;
          }
        } catch (_) {
          if (meta) meta.content = target;
        }
        syncUI();
      });
    }
    mql.addEventListener("change", syncUI);

    let supportsDisplayTransition;
    function canTransitionDisplay() {
      if (supportsDisplayTransition !== undefined) return supportsDisplayTransition;
      if (!window.CSS?.supports?.("transition-behavior", "allow-discrete") || !document.body) return false;
      const probe = document.createElement("div");
      probe.style.cssText = "transition: display 1s allow-discrete !important; display: block;";
      document.body.appendChild(probe);
      getComputedStyle(probe).display;
      probe.style.display = "none";
      supportsDisplayTransition = getComputedStyle(probe).display === "block";
      probe.remove();
      return supportsDisplayTransition;
    }

    function supportsTopLayerExit() {
      return window.CSS?.supports?.("overlay", "auto") && canTransitionDisplay();
    }

    async function closeTopLayer(dialog) {
      if (!dialog.open) return;
      if (!supportsTopLayerExit()) {
        dialog.setAttribute("data-closing", "");
        const anims = dialog.getAnimations ? dialog.getAnimations({ subtree: true }) : [];
        if (anims.length > 0) {
          await Promise.race([
            Promise.allSettled(anims.map((a) => a.finished)),
            new Promise((r) => setTimeout(r, 400)),
          ]);
        }
        if (!dialog.hasAttribute("data-closing")) return;
        dialog.removeAttribute("data-closing");
      }
      dialog.close();
    }

    document.querySelectorAll("dialog").forEach((dialog) => {
      dialog.addEventListener("cancel", (event) => {
        if (!supportsTopLayerExit()) {
          event.preventDefault();
          closeTopLayer(dialog);
        }
      });
      if (!("closedBy" in HTMLDialogElement.prototype)) {
        dialog.addEventListener("click", (ev) => {
          if (ev.target !== dialog) return;
          const r = dialog.getBoundingClientRect();
          const inside = r.top <= ev.clientY && ev.clientY <= r.top + r.height && r.left <= ev.clientX && ev.clientX <= r.left + r.width;
          if (!inside) closeTopLayer(dialog);
        });
      }
    });
  }

  // ==================== 6. INTERACTIVE HUMAN-VS-AI CONTAINMENT SIMULATOR ====================
  function initContainmentSimulator() {
    const sel = document.getElementById("sim-scenario-select");
    const slider = document.getElementById("sim-soc-slider");
    const lbl = document.getElementById("sim-soc-label");
    const kpiRow = document.getElementById("sim-kpi-row");
    const svg = document.getElementById("sim-curve-svg");
    const banner = document.getElementById("sim-verdict-banner");
    const pill = document.getElementById("sim-mode-pill");
    const humanComp = document.getElementById("sim-human-comparison");
    if (!sel || !slider || !svg) return;

    function getLayers() {
      const state = {};
      document.querySelectorAll("[data-sim-layer]").forEach((cb) => {
        state[cb.dataset.simLayer] = cb.checked;
      });
      return state;
    }

    function renderSim() {
      const sc = SIM_SCENARIOS[sel.value] || SIM_SCENARIOS.upbit_solana;
      const socMin = Number(slider.value);
      if (lbl) lbl.textContent = `${socMin} min`;
      const layers = getLayers();

      // Human SOC modeled loss
      const humanLossM = sc.mode === "atomic"
        ? sc.maxLossM
        : sc.maxLossM * Math.min(1, socMin / sc.drainDurationMin);

      // InfiniteSecurity autonomous modeled loss
      let aiLossM = humanLossM;
      let stopDesc = "No InfiniteSecurity layers enabled (falls back to legacy human SOC response)";
      let aiLatencyLabel = `${socMin} min (human)`;
      let uptimeLabel = sc.humanFreezeLabel;
      let stoppedPreEvent = false;

      if ((layers.premerge && sc.premergeStops) || (layers.oob && sc.oobStops) || (layers.crypto && sc.cryptoStops)) {
        aiLossM = 0;
        stoppedPreEvent = true;
        const activeStops = [];
        if (layers.premerge && sc.premergeStops) activeStops.push("L1 Pre-Merge CI (<45s)");
        if (layers.oob && sc.oobStops) activeStops.push("L3 Out-of-Band Byte Verifier (<200ms)");
        if (layers.crypto && sc.cryptoStops) activeStops.push("L4 FROST + ZKP + MTD");
        stopDesc = `Stopped pre-loss autonomously by ${activeStops.join(" + ")}`;
        aiLatencyLabel = layers.oob && sc.oobStops ? "< 200 ms" : "< 45s CI";
        uptimeLabel = "100% (12/12 SLAs Live)";
      } else if (layers.breaker) {
        aiLossM = Math.min(humanLossM, sc.breakerCapM);
        stopDesc = `Contained in <3s by Layer 5 T+0 Ledger Reconciliation & LLR-CUSUM Circuit Breaker`;
        aiLatencyLabel = "< 3 sec";
        uptimeLabel = "100% (Scoped cut · 12/12 SLAs Live)";
      }

      const savedPct = humanLossM > 0 ? Math.max(0, ((humanLossM - aiLossM) / humanLossM) * 100) : 100;
      const enabledCount = Object.values(layers).filter(Boolean).length;

      if (pill) {
        pill.className = `pill ${aiLossM === 0 ? "pill-ship" : aiLossM < humanLossM * 0.15 ? "pill-restrict" : "pill-hold"}`;
        pill.textContent = aiLossM === 0 ? "100% PREVENTED PRE-LOSS" : enabledCount > 0 ? `${savedPct.toFixed(1)}% LOSS CUT` : "UNPROTECTED (HUMAN SOC)";
      }

      if (kpiRow) {
        kpiRow.innerHTML = `
          <div class="inc-stat" style="border-left:4px solid var(--danger);">
            <div class="k">LEGACY HUMAN SOC (${socMin}m MTTD)</div>
            <div class="v tnum" style="font-size:1.25rem; color:var(--danger);">${fmtUsdM(humanLossM)}</div>
            <div class="muted" style="font-size:0.76rem;">${sc.humanTouchpoints} manual handoffs</div>
          </div>
          <div class="inc-stat" style="border-left:4px solid var(--ok);">
            <div class="k">INFINITESECURITY (${aiLatencyLabel})</div>
            <div class="v tnum" style="font-size:1.25rem; color:var(--ok);">${fmtUsdM(aiLossM)}</div>
            <div class="muted" style="font-size:0.76rem;">${savedPct.toFixed(1)}% reduction · 0 keys held</div>
          </div>
          <div class="inc-stat" style="border-left:4px solid var(--c-code);">
            <div class="k">CUSTOMER WITHDRAWAL UPTIME</div>
            <div class="v" style="font-size:0.96rem; color:${enabledCount > 0 ? "var(--ok)" : "var(--danger)"};">${esc(uptimeLabel)}</div>
          </div>
        `;
      }

      if (banner) {
        banner.style.setProperty("--bc", aiLossM === 0 ? "var(--ok)" : enabledCount > 0 ? "var(--warn)" : "var(--danger)");
        banner.innerHTML = `<div><span class="eyebrow" style="color:${aiLossM === 0 ? "var(--ok)" : "var(--warn)"};">AUTONOMOUS INTERCEPTION VERDICT</span><p style="font-size:0.88rem; margin-top:4px;"><strong>${esc(stopDesc)}.</strong> ${escCode(sc.summary)}</p></div>`;
      }

      if (humanComp) {
        humanComp.innerHTML = `<strong>Human Dependency Delta:</strong> Legacy flow required <strong>${sc.humanTouchpoints} manual detection/escalation steps</strong> and resulted in <em>${esc(sc.humanFreezeLabel)}</em>. InfiniteSecurity replaces those human bottlenecks with deterministic machine gates at <strong>${esc(aiLatencyLabel)}</strong>.`;
      }

      // Draw SVG Loss-vs-Time Curve (0..60 min)
      const W = 600, H = 230, px0 = 56, px1 = 574, py0 = 24, py1 = 188;
      const xForMin = (m) => px0 + (m / 60) * (px1 - px0);
      const yForLoss = (loss) => py1 - (loss / Math.max(0.1, sc.maxLossM)) * (py1 - py0);

      let humanPts = [];
      for (let m = 0; m <= 60; m += 2) {
        const effM = Math.min(m, socMin);
        const l = sc.mode === "atomic" ? (m >= 1 ? sc.maxLossM : 0) : sc.maxLossM * Math.min(1, effM / sc.drainDurationMin);
        humanPts.push(`${xForMin(m).toFixed(1)},${yForLoss(l).toFixed(1)}`);
      }
      const aiY = yForLoss(aiLossM).toFixed(1);
      const socX = xForMin(socMin).toFixed(1);
      const humanFinalY = yForLoss(humanLossM).toFixed(1);

      svg.innerHTML = `
        <line x1="${px0}" y1="${py1}" x2="${px1}" y2="${py1}" stroke="var(--line-2)" stroke-width="1.4"/>
        <line x1="${px0}" y1="${py0}" x2="${px0}" y2="${py1}" stroke="var(--line-2)" stroke-width="1.4"/>
        <line x1="${px0}" y1="${py0}" x2="${px1}" y2="${py0}" stroke="var(--line)" stroke-dasharray="3 4"/>
        <text x="${px0 - 8}" y="${py0 + 4}" text-anchor="end" fill="var(--ink-3)" font-family="var(--mono)" font-size="10">${fmtUsdM(sc.maxLossM)}</text>
        <text x="${px0 - 8}" y="${py1 + 4}" text-anchor="end" fill="var(--ink-3)" font-family="var(--mono)" font-size="10">$0</text>
        <text x="${px0}" y="${H - 14}" fill="var(--ink-3)" font-family="var(--mono)" font-size="10">0m (Attack T-0)</text>
        <text x="${xForMin(30).toFixed(1)}" y="${H - 14}" text-anchor="middle" fill="var(--ink-3)" font-family="var(--mono)" font-size="10">30m</text>
        <text x="${px1}" y="${H - 14}" text-anchor="end" fill="var(--ink-3)" font-family="var(--mono)" font-size="10">60m</text>

        <polyline fill="none" stroke="var(--danger)" stroke-width="3" points="${humanPts.join(" ")}"/>
        <line x1="${socX}" y1="${py0}" x2="${socX}" y2="${py1}" stroke="var(--danger)" stroke-dasharray="4 4" stroke-width="1.3"/>
        <circle cx="${socX}" cy="${humanFinalY}" r="5" fill="var(--danger)"/>
        <text x="${Math.min(px1 - 120, Number(socX) + 8)}" y="${Math.max(py0 + 14, Number(humanFinalY) - 8)}" fill="var(--danger)" font-family="var(--mono)" font-weight="700" font-size="10.5">Human SOC (${socMin}m): ${fmtUsdM(humanLossM)}</text>

        <line x1="${px0}" y1="${aiY}" x2="${px1}" y2="${aiY}" stroke="var(--c-sla)" stroke-width="3.2"/>
        <circle cx="${px0 + 6}" cy="${aiY}" r="5.5" fill="var(--c-sla)"/>
        <text x="${px0 + 18}" y="${Math.min(py1 - 8, Number(aiY) - 8)}" fill="var(--c-sla)" font-family="var(--mono)" font-weight="700" font-size="11">InfiniteSecurity (${stoppedPreEvent ? aiLatencyLabel : "<3s breaker"}): ${fmtUsdM(aiLossM)}</text>
      `;
    }

    sel.addEventListener("change", renderSim);
    slider.addEventListener("input", renderSim);
    document.querySelectorAll("[data-sim-layer]").forEach((cb) => cb.addEventListener("change", renderSim));
    renderSim();
  }

  // ==================== 7. 4-TAB FORENSIC & CODE WORKBENCH MODAL ====================
  function openIncidentCodeModal(incidentId) {
    const inc = INCIDENTS.find((x) => x.id === incidentId);
    const modal = document.getElementById("incident-code-modal");
    if (!inc || !modal) return;

    const eye = document.getElementById("inc-modal-eyebrow");
    const ttl = document.getElementById("inc-modal-title");
    const pill = document.getElementById("inc-modal-pill");
    const sum = document.getElementById("inc-modal-summary");
    const body = document.getElementById("inc-modal-body");

    if (eye) {
      eye.textContent = `${inc.date.toUpperCase()} · ${inc.catLabel.toUpperCase()}`;
      eye.style.color = inc.color;
    }
    if (ttl) ttl.textContent = `${inc.venue} — 4-Tab Autonomous Defense & Code Forensics`;
    if (pill) pill.textContent = `${inc.autonomyPct}% AUTONOMOUS`;
    if (sum) sum.innerHTML = `<strong>Historical Loss:</strong> ${esc(inc.lossReported)} · <strong>Modeled Counterfactual:</strong> ${esc(inc.modeledOutcome)}`;

    const vulnLines = inc.vulnCode.split("\n");
    const safeLines = inc.safeCode.split("\n");
    const ad = inc.activeDefense;
    const cf = inc.counterfactual;

    if (body) {
      body.innerHTML = `
        <div class="modal-metrics-4">
          <div class="inc-stat"><div class="k">HISTORICAL MTTD / LOSS</div><div class="v" style="color:var(--danger);">${esc(cf.humanLoss)}</div></div>
          <div class="inc-stat"><div class="k">INFINITESECURITY LATENCY</div><div class="v" style="color:var(--ok);">${esc(cf.aiLatency)}</div></div>
          <div class="inc-stat"><div class="k">MODELED AI OUTCOME</div><div class="v" style="color:var(--ok);">${esc(cf.aiLoss)}</div></div>
          <div class="inc-stat"><div class="k">HUMAN BOTTLENECKS</div><div class="v">${esc(cf.aiTouchpoints)}</div></div>
        </div>

        <div id="inc-modal-tabs-root">
          <div class="modal-tablist" role="tablist" aria-label="Incident forensic views">
            <button type="button" class="modal-tab" role="tab" id="mtab-code" aria-selected="true" data-mtab="mpanel-code">1. Exploited vs. Defended Code</button>
            <button type="button" class="modal-tab" role="tab" id="mtab-mitre" aria-selected="false" data-mtab="mpanel-mitre">2. MITRE ATT&amp;CK Kill-Chain (${inc.mitreKillChain.length})</button>
            <button type="button" class="modal-tab" role="tab" id="mtab-active" aria-selected="false" data-mtab="mpanel-active">3. 4-Tier Active Defense &amp; Reconciliation</button>
            <button type="button" class="modal-tab" role="tab" id="mtab-receipt" aria-selected="false" data-mtab="mpanel-receipt">4. Counterfactual &amp; Machine Receipt</button>
          </div>

          <!-- TAB 1: EXPLOITED VS DEFENDED CODE -->
          <div role="tabpanel" id="mpanel-code" aria-labelledby="mtab-code" tabindex="0">
            <div class="modal-panel-inner">
              <div class="code-modal-split">
                <div style="display:grid; gap:12px;">
                  <div class="ide-window">
                    <div class="ide-topbar">
                      <span class="mono" style="font-size:11.5px; color:#ffa198;">${esc(inc.vulnFilename)}</span>
                      <span class="pill pill-hold">Exploited Root Cause</span>
                    </div>
                    <div class="code-scroll" style="max-height:260px;">
                      ${vulnLines.map((ln, idx) => `<div class="code-line del"><span class="ln">${idx + 1}</span><span class="sig">-</span><span>${esc(ln)}</span></div>`).join("")}
                    </div>
                  </div>

                  <div class="ide-window">
                    <div class="ide-topbar">
                      <span class="mono" style="font-size:11.5px; color:#7ee787;">${esc(inc.safeFilename)}</span>
                      <span class="copy">
                        <button type="button" class="copy-button" command="--copy" commandfor="inc-modal-safe-raw" aria-label="Copy InfiniteSecurity guard code">Copy guard</button>
                        <span class="tip" role="status"></span>
                      </span>
                    </div>
                    <div class="code-scroll" style="max-height:300px;">
                      ${safeLines.map((ln, idx) => `<div class="code-line add"><span class="ln">${idx + 1}</span><span class="sig">+</span><span>${esc(ln)}</span></div>`).join("")}
                    </div>
                    <pre id="inc-modal-safe-raw" class="visually-hidden">${esc(inc.safeCode)}</pre>
                  </div>
                </div>

                <div class="issue-stack">
                  <span class="eyebrow">WHY HUMANS MISSED IT &amp; HOW INFINITESECURITY AUTOMATES DEFENSE</span>
                  <article class="issue-card ok">
                    <h4><span>Autonomous Interception Layer</span><span class="pill pill-ship">${inc.autonomyPct}% AI-Driven</span></h4>
                    <p>${escCode(inc.interceptionLayer)}</p>
                    <div class="issue-fix">${esc(inc.autonomyLabel)}</div>
                  </article>
                  ${inc.issues.map((iss) => {
                    const sevCls = iss.sev === "CRITICAL" ? "" : "warn";
                    const pillCls = iss.sev === "CRITICAL" ? "pill-hold" : "pill-restrict";
                    return `<article class="issue-card ${sevCls}">
                      <h4><span>${esc(iss.title)}</span><span class="pill ${pillCls}">${esc(iss.sev)}</span></h4>
                      <p>${escCode(iss.detail)}</p>
                      <div class="issue-fix">Autonomous Fix: ${escCode(iss.fix)}</div>
                    </article>`;
                  }).join("")}
                </div>
              </div>
            </div>
          </div>

          <!-- TAB 2: MITRE ATT&CK KILL-CHAIN MATRIX -->
          <div role="tabpanel" id="mpanel-mitre" aria-labelledby="mtab-mitre" hidden="until-found">
            <div class="modal-panel-inner">
              <p class="muted" style="font-size:0.9rem;">Every stage of the historical kill chain mapped directly to the human blind spot it exploited and the exact deterministic InfiniteSecurity layer that severs it autonomously.</p>
              <div style="overflow-x:auto; border:1px solid var(--line); border-radius:var(--r-md);">
                <table class="mitre-table">
                  <thead>
                    <tr>
                      <th>MITRE Tactic &amp; Technique</th>
                      <th>Attacker Action</th>
                      <th>Human / Legacy Blind Spot</th>
                      <th>InfiniteSecurity Autonomous Interception</th>
                      <th>Speed</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${inc.mitreKillChain.map((row) => `
                      <tr>
                        <td><strong>${esc(row.tactic)}</strong><br><span class="mono" style="font-size:0.76rem; color:var(--c-ai);">${esc(row.technique)}</span></td>
                        <td>${escCode(row.attackerAction)}</td>
                        <td style="color:var(--danger);">${escCode(row.humanBlindSpot)}</td>
                        <td style="color:var(--ok); font-weight:600;">${escCode(row.aiStop)}</td>
                        <td class="mono" style="white-space:nowrap; font-weight:700;">${esc(row.latency)}</td>
                      </tr>
                    `).join("")}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <!-- TAB 3: 4-TIER APPROVAL, ACTIVE DEFENSE & RECONCILIATION -->
          <div role="tabpanel" id="mpanel-active" aria-labelledby="mtab-active" hidden="until-found">
            <div class="modal-panel-inner">
              <div class="tier-4-grid">
                <article class="issue-card ok">
                  <h4><span>Tier 1 · Device &amp; Identity Isolation</span><span class="pill pill-ship">PRE-SIGN</span></h4>
                  <p>${escCode(ad.tier1)}</p>
                </article>
                <article class="issue-card ok">
                  <h4><span>Tier 2 · Quorum, Proof &amp; Airlock</span><span class="pill pill-ship">CRYPTOGRAPHIC</span></h4>
                  <p>${escCode(ad.tier2)}</p>
                </article>
                <article class="issue-card ok">
                  <h4><span>Tier 3 · Bytecode &amp; Entropy Audit</span><span class="pill pill-ship">ZERO-TRUST OOB</span></h4>
                  <p>${escCode(ad.tier3)}</p>
                </article>
                <article class="issue-card ok">
                  <h4><span>Tier 4 · Velocity Caps &amp; Business Logic</span><span class="pill pill-ship">&lt;3S BREAKER</span></h4>
                  <p>${escCode(ad.tier4)}</p>
                </article>
              </div>
              <div class="acc-cols">
                <div class="inc-stat"><div class="k">TRIPLE-LAYER WALLET POLICY</div><div class="v">${escCode(ad.walletCap)}</div></div>
                <div class="inc-stat"><div class="k">CONTINUOUS RECONCILIATION</div><div class="v">${escCode(ad.reconciliation)}</div></div>
                <div class="inc-stat"><div class="k">ACTIVE DEFENSE MECHANISM</div><div class="v" style="color:var(--ok);">${escCode(ad.activeMechanism)}</div></div>
              </div>
            </div>
          </div>

          <!-- TAB 4: COUNTERFACTUAL MATH & MACHINE RECEIPT -->
          <div role="tabpanel" id="mpanel-receipt" aria-labelledby="mtab-receipt" hidden="until-found">
            <div class="modal-panel-inner">
              <div class="vs-2-grid">
                <article class="vs-card" style="--vc: var(--danger); padding:14px 16px;">
                  <span class="eyebrow" style="color:var(--danger)">HISTORICAL HUMAN-DEPENDENT OUTCOME</span>
                  <ul class="vs-list">
                    <li><strong>Detection / Timeline:</strong> ${esc(cf.humanMttd)}</li>
                    <li><strong>Reported Loss:</strong> ${esc(cf.humanLoss)}</li>
                    <li><strong>Human Bottlenecks:</strong> ${esc(cf.humanTouchpoints)}</li>
                    <li><strong>Customer Uptime:</strong> ${esc(cf.humanUptime)}</li>
                  </ul>
                </article>
                <article class="vs-card" style="--vc: var(--c-sla); padding:14px 16px;">
                  <span class="eyebrow" style="color:var(--c-sla)">INFINITESECURITY AUTONOMOUS COUNTERFACTUAL</span>
                  <ul class="vs-list">
                    <li><strong>Machine Stop Latency:</strong> ${esc(cf.aiLatency)}</li>
                    <li><strong>Modeled Loss:</strong> ${esc(cf.aiLoss)}</li>
                    <li><strong>Runtime Human Bottlenecks:</strong> ${esc(cf.aiTouchpoints)}</li>
                    <li><strong>Customer Uptime:</strong> ${esc(cf.aiUptime)}</li>
                  </ul>
                </article>
              </div>

              <div class="ide-window">
                <div class="ide-topbar">
                  <span class="mono" style="font-size:11.5px; color:#93c5fd;">SIGNED TAMPER-EVIDENT MACHINE VERDICT (SHA-256 AUDIT LEDGER)</span>
                  <span class="copy">
                    <button type="button" class="copy-button" command="--copy" commandfor="inc-modal-receipt-raw" aria-label="Copy JSON receipt">Copy JSON</button>
                    <span class="tip" role="status"></span>
                  </span>
                </div>
                <div class="code-scroll" style="padding:12px 14px;">
                  <pre class="mini-code" id="inc-modal-receipt-raw" style="margin:0; border:0; padding:0;">${esc(cf.receiptJson)}</pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      `;

      // Wire accessible modal tab switching + `beforematch` sync (`modern-web-guidance`: tabs + search-hidden-content)
      const root = document.getElementById("inc-modal-tabs-root");
      const tabs = [...root.querySelectorAll('[role="tab"]')];
      const panels = [...root.querySelectorAll('[role="tabpanel"]')];

      function activateModalTab(panelId) {
        tabs.forEach((t) => {
          const on = t.dataset.mtab === panelId;
          t.setAttribute("aria-selected", String(on));
        });
        panels.forEach((p) => {
          const on = p.id === panelId;
          if (on) {
            p.hidden = false;
            p.setAttribute("tabindex", "0");
          } else {
            p.setAttribute("hidden", "until-found");
            p.removeAttribute("tabindex");
          }
        });
      }

      tabs.forEach((t) => {
        t.addEventListener("click", () => activateModalTab(t.dataset.mtab));
      });
      root.addEventListener("beforematch", (ev) => {
        const panel = ev.target.closest('[role="tabpanel"]');
        if (panel) activateModalTab(panel.id);
      });
    }

    if (!modal.open) modal.showModal();
  }

  // ==================== 8. RENDER CARDS, COMPARISON MATRIX & 32-ROW EMPIRICAL LEDGER ====================
  let activeCat = "all";
  let searchQuery = "";

  function filteredIncidents() {
    const q = searchQuery.trim().toLowerCase();
    return INCIDENTS.filter((inc) => {
      if (activeCat !== "all" && inc.category !== activeCat) return false;
      if (!q) return true;
      const hay = [
        inc.venue, inc.date, inc.catLabel, inc.attacker,
        inc.humanFailure, inc.interceptionLayer, inc.vulnCode, inc.safeCode,
        ...(inc.mitreTags || [])
      ].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }

  function renderCards() {
    const grid = document.getElementById("incident-cards-grid");
    if (!grid) return;
    const rows = filteredIncidents();
    if (!rows.length) {
      grid.innerHTML = `<div class="control-box"><p class="muted">No incidents matched your filter. Try clearing the search box or choosing "All 10 Cases".</p></div>`;
      return;
    }

    grid.innerHTML = rows.map((inc) => `
      <article class="inc-card" style="--ic:${inc.color}">
        <div class="inc-head">
          <div>
            <span class="eyebrow" style="color:${inc.color}">${esc(inc.date)} · ${esc(inc.catLabel)}</span>
            <h3 style="margin-top:3px; font-size:1.22rem;">${esc(inc.venue)}</h3>
          </div>
          <span class="pill pill-hold">${esc(inc.lossReported)}</span>
        </div>

        <div class="mitre-tags" aria-label="MITRE ATT&CK and root-cause tags">
          ${(inc.mitreTags || []).map((tag) => `<span class="mitre-chip">${esc(tag)}</span>`).join("")}
        </div>

        <p style="font-size:0.91rem; color:var(--ink-2);">
          <strong>Human &amp; Operational Seam Exploited:</strong> ${escCode(inc.humanFailure)}
        </p>

        <div class="inc-meta-strip">
          <div class="inc-stat">
            <div class="k">THREAT ACTOR</div>
            <div class="v">${esc(inc.attacker)}</div>
          </div>
          <div class="inc-stat">
            <div class="k">AUTONOMOUS SEAM</div>
            <div class="v">${escCode(inc.interceptionLayer.split("+")[0].trim())}</div>
          </div>
          <div class="inc-stat">
            <div class="k">MODELED OUTCOME</div>
            <div class="v" style="color:var(--ok);">${esc(inc.modeledOutcome.split("(")[0].trim())}</div>
          </div>
        </div>

        <div class="autonomy-meter">
          <div style="display:flex; justify-content:space-between; font:700 11.5px/1.2 var(--mono);">
            <span style="color:var(--ink-3);">AI AUTONOMY (LOW HUMAN DEPENDENCY)</span>
            <span style="color:var(--c-sla);">${inc.autonomyPct}% MACHINE-ENFORCED</span>
          </div>
          <div class="autonomy-bar-track" role="progressbar" aria-valuenow="${inc.autonomyPct}" aria-valuemin="0" aria-valuemax="100">
            <div class="autonomy-bar-fill" style="width:${inc.autonomyPct}%;"></div>
          </div>
          <span style="font-size:0.8rem; color:var(--ink-2);">${esc(inc.autonomyLabel)}</span>
        </div>

        <div class="inc-timeline">
          ${inc.timeline.map((st) => `
            <div class="inc-step ${st.intercept ? "intercept" : ""}">
              <span class="inc-step-t">${esc(st.t)}</span>
              <span>${escCode(st.txt)}</span>
            </div>
          `).join("")}
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; margin-top:2px;">
          <span class="pill pill-ship">0 Private Keys Held · 4-Tab Forensics</span>
          <button type="button" class="btn sm" data-inspect-inc="${esc(inc.id)}">Open 4-Tab Forensic &amp; Code Workbench ↗</button>
        </div>
      </article>
    `).join("");

    grid.querySelectorAll("[data-inspect-inc]").forEach((btn) => {
      btn.addEventListener("click", () => openIncidentCodeModal(btn.dataset.inspectInc));
    });
  }

  function renderMatrix() {
    const tbody = document.getElementById("incident-matrix-tbody");
    if (!tbody) return;
    const table = document.getElementById("incident-matrix-table");
    if (table) {
      table.style.setProperty("--label-2", '"Historical Loss"');
      table.style.setProperty("--label-3", '"Root Cause"');
      table.style.setProperty("--label-4", '"Autonomous Stop"');
      table.style.setProperty("--label-5", '"Modeled Reduction"');
      table.style.setProperty("--label-6", '"Code"');
    }

    tbody.innerHTML = INCIDENTS.map((inc) => `
      <tr>
        <th scope="row">
          <div>${esc(inc.venue)}</div>
          <div class="mono" style="font-size:0.75rem; color:var(--ink-3); font-weight:600;">${esc(inc.date)}</div>
        </th>
        <td class="tnum" style="font-weight:700; color:var(--danger);">${esc(inc.lossReported)}</td>
        <td>${escCode(inc.humanFailure)}</td>
        <td>${escCode(inc.interceptionLayer)}</td>
        <td style="color:var(--ok); font-weight:600;">${esc(inc.modeledOutcome)}</td>
        <td>
          <button type="button" class="btn ghost sm" data-matrix-inc="${esc(inc.id)}">Inspect Code ↗</button>
        </td>
      </tr>
    `).join("");

    tbody.querySelectorAll("[data-matrix-inc]").forEach((btn) => {
      btn.addEventListener("click", () => openIncidentCodeModal(btn.dataset.matrixInc));
    });
  }

  function renderEmpiricalLedger() {
    const tbody = document.getElementById("empirical-ledger-tbody");
    const table = document.getElementById("empirical-ledger-table");
    if (!tbody) return;
    if (table) {
      table.style.setProperty("--label-2", '"Reported Loss"');
      table.style.setProperty("--label-3", '"Root Cause"');
      table.style.setProperty("--label-4", '"Category"');
      table.style.setProperty("--label-5", '"Recovery"');
      table.style.setProperty("--label-6", '"InfiniteSecurity Pillar"');
    }

    tbody.innerHTML = EMPIRICAL_LEDGER.map(([ex, yr, loss, cause, cat, rec, pillar]) => `
      <tr>
        <th scope="row">
          <div>${esc(ex)}</div>
          <div class="mono" style="font-size:0.75rem; color:var(--ink-3); font-weight:600;">${esc(yr)}</div>
        </th>
        <td class="tnum" style="font-weight:700; color:var(--danger);">${esc(loss)}</td>
        <td>${escCode(cause)}</td>
        <td><span class="mitre-chip">${esc(cat)}</span></td>
        <td class="muted">${esc(rec)}</td>
        <td style="color:var(--ok); font-weight:600;">${escCode(pillar)}</td>
      </tr>
    `).join("");
  }

  // ==================== 9. INIT ====================
  document.addEventListener("DOMContentLoaded", () => {
    initCopyButtons();
    initAccordionToggleAll();
    initThemeAndDialogFallbacks();
    initContainmentSimulator();

    document.querySelectorAll("#incident-filter-bar [data-cat]").forEach((btn) => {
      btn.addEventListener("click", () => {
        activeCat = btn.dataset.cat;
        document.querySelectorAll("#incident-filter-bar [data-cat]").forEach((b) => {
          const on = b === btn;
          b.setAttribute("aria-selected", String(on));
          b.classList.toggle("ghost", !on);
        });
        renderCards();
      });
    });

    const searchInput = document.getElementById("incident-search");
    if (searchInput) {
      searchInput.addEventListener("input", () => {
        searchQuery = searchInput.value;
        renderCards();
      });
    }

    renderCards();
    renderMatrix();
    renderEmpiricalLedger();
  });
})();
