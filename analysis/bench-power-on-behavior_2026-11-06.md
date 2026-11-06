# Bench outcome: power-on behavior measured on a smart plug (2026-11-06)

We built an automated bench to measure the power-on behavior of the stock bulb
with correlated MQTT reads, instead of anecdotes: one sacrificial TS0505A
(Luce_studio, the same unit used for the OTA attempts) powered through a
Silvercrest TS011F smart plug (Presa_Lidl), driven over Zigbee2MQTT.

## Result (observational)

Every completed trial observed the bulb ON after mains restore:

| campaign | trials | pre-cut verified | post-restore reads | verdict |
|---|---|---|---|---|
| 2026-11-05 night (runner v1) | 3 | 1x ON, 2x OFF (weak, see below) | ON + ON per trial | ON observed |
| 2026-11-06 (runner v3) | 3 | ON/ON, OFF/OFF, OFF/OFF | ON + ON per trial | ON observed |

Across both campaigns: 6 cuts, 4 of them with the pre-cut OFF state verified by
paired agreeing reads before the cut (temporal correlation: reads after the get,
before the cut, margins 96-145 ms in the v3 journal), and the bulb came back ON
every time. This is a repeated, consistent observation on one unit: the stock
bulb does not restore its previous OFF state after a mains cut.

What this is NOT, stated plainly:

- It is not a formal proof of a boot policy: the MQTT boundary (Z2M with
  `log_level: info`) cannot carry ZCL readResponse provenance or transaction
  numbers, so read attribution remains "device-originated, best effort"
  (A2 in the review below).
- "Zero contamination events" is the runner filter's output, not proof that no
  other actor wrote to the devices (known gaps: `/set/state` subtopics and raw
  broker events are not journaled).
- No claim about the optical flash at power-on, about the whole TS0505A family,
  or about more than this one unit.

## Runner honesty: three revisions, two rejected by review

The bench runner went through adversarial review (a second agent reproducing
defects offline against the real compiled code), and we publish the outcome
including the rejects because they are the reason the final numbers are
trustworthy:

- v1 (2026-11-05): produced the ON observations but was rejected: the pre-cut
  verification could accept a publication older than the read it claimed
  (0.5 s slack), the first read after restore started only after a fixed ~315 s
  program wait, contamination detection covered two exact topics only and did
  not stop the campaign. Those three ON observations stand as observations;
  the run's policy claim was reclassified INCONCLUSIVE.
- v2 (2026-11-06): fixed the read correlation (quiet-window rule, strict
  ordering, paired agreeing reads) but the review found 12 more counterexamples
  (counter incremented after the trial instead of before the cut, journal only
  in RAM and lost on interruption, restore that disarmed the watchdog even on
  failure, one-shot watchdog that could re-publish). One supervised trial was
  run and then the campaign was paused on the reviewer's request.
- v3 (2026-11-06, frozen then run): cycle counter reserved and persisted before
  each cut, append-only JSONL journal fsynced per record during the run,
  restore verified by plug feedback before disarming the independent watchdog,
  atomic lease, one-to-one own-publish matching. 24 offline tests (including
  reproductions of every review counterexample) pass against the frozen
  package; SHA256 in the delivery notes. The same review still lists seven
  operational invariants as broken (e.g. a crash window between the OFF publish
  and the plug-state persist in which the watchdog is blind), so the runner is
  NOT approved for unattended use; the final campaign of 3 cuts was run
  supervised by the operator acting as active recovery, on the owner's explicit
  order, with those gates declared skipped.

The v3 journal (73 monotonic records) shows for every trial: `cut_intent`
persisted before the OFF publish, pre-cut state confirmed by paired reads after
the gets and before the cut, ON publications after the restore, and the cycle
counter walking 5, 6, 7 against a budget of 8.

## Files

- `evidence/bench-v1-run_2026-11-05.json` - v1 run (superseded, kept immutable)
- `evidence/bench-v3-run_2026-11-06.json` - v3 export (3 trials, verdicts, manifest)
- `evidence/bench-v3-journal_2026-11-06.jsonl` - v3 append-only journal

## Interpretation for this repository

The bench closes the last open question the OTA campaign left about the stock
behavior: there is no hidden power-on setting reachable from the outside. The
documented channels are rejected by the firmware (see README), the bootloader
rejects every custom image (rounds 7-13), and the measured behavior is
always-ON-at-restore regardless of the pre-cut state. Mitigating the blackout
nuisance therefore remains an automation problem (cut power, or accept the ON),
not a firmware setting.
