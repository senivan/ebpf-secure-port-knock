# XDP Performance Report

Run directory: `/home/user/ebpf-secure-port-knock/artifacts/perf-20260505-184832`

## Environment

| Field | Value |
| --- | --- |
| bpftool | `bpftool v7.6.0` |
| clang | `clang version 21.1.8 (Fedora 21.1.8-4.fc43)` |
| cpu_count | `32` |
| cpu_model | `Intel(R) Xeon(R) CPU E5-2690 v4 @ 2.60GHz` |
| date | `2026-05-05T18:48:33+03:00` |
| git_commit | `03fe95c899d39e0a681677e0a77b9303149242d9` |
| git_status_short | `M Makefile
 M README.md
?? .codex
?? artifacts/
?? performance-report.md
?? scripts/perf_xdp_netns.sh
?? tools/` |
| kernel | `6.19.14-200.fc43.x86_64` |
| machine | `x86_64` |
| out_dir | `/home/user/ebpf-secure-port-knock/artifacts/perf-20260505-184832` |
| perf | `perf version 6.19.14-200.fc43.x86_64` |

## Results Summary

| Scenario | Trials | Median PPS | Min PPS | Max PPS | Stddev | Status |
| --- | --- | --- | --- | --- | --- | --- |
| baseline_no_xdp | 1 | 303333 | 303333 | 303333 | 0 | ok |
| xdp_unprotected_pass | 1 | 243826 | 243826 | 243826 | 0 | ok |
| protected_unauthorized_drop | 1 | 260851 | 260851 | 260851 | 0 | ok |
| knock_invalid_user_or_key | 1 | 269315 | 269315 | 269315 | 0 | ok |
| authorized_protected_pass | 1 | 254171 | 254171 | 254171 | 0 | ok |
| replay_drop | 1 | 162321 | 162321 | 162321 | 0 | ok |
| source_rate_limit | 1 | 164126 | 164126 | 164126 | 0 | ok |
| active_session_pressure_32 | 1 | 228317 | 228317 | 228317 | 0 | ok |
| user_scale_128 | 1 | 170913 | 170913 | 170913 | 0 | ok |
| user_scale_1024 | 1 | 164350 | 164350 | 164350 | 0 | ok |

## Graphs

- [Median PPS by scenario](pps_by_scenario.svg)
- [PPS by trial](pps_trials.svg)
- [XDP counter deltas](xdp_counter_deltas.svg)
- [CPU task-clock per MPPS](cpu_per_mpps.svg)
- [Drop vs pass PPS](drop_vs_pass_pps.svg)
- [Session pressure PPS](session_pressure_pps.svg)
- [User scale PPS](user_scale_pps.svg)
- [Timeseries PPS and drops](timeseries_pps_and_drops.svg)

## Raw Data

- `results.csv`
- `stats_timeseries.csv`
- `environment.json`
- `knockd.log`
- `build.log`
