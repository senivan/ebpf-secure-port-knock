# XDP Performance Report

Run directory: `/home/user/ebpf-secure-port-knock/artifacts/perf-20260505-185449`

## Environment

| Field | Value |
| --- | --- |
| bpftool | `bpftool v7.6.0` |
| clang | `clang version 21.1.8 (Fedora 21.1.8-4.fc43)` |
| cpu_count | `32` |
| cpu_model | `Intel(R) Xeon(R) CPU E5-2690 v4 @ 2.60GHz` |
| date | `2026-05-05T18:54:49+03:00` |
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
| out_dir | `/home/user/ebpf-secure-port-knock/artifacts/perf-20260505-185449` |
| perf | `perf version 6.19.14-200.fc43.x86_64` |

## Results Summary

| Scenario | Trials | Median PPS | Min PPS | Max PPS | Stddev | Status |
| --- | --- | --- | --- | --- | --- | --- |
| baseline_no_xdp | 3 | 220918 | 213069 | 223362 | 4391 | ok |
| xdp_unprotected_pass | 3 | 190123 | 188490 | 190489 | 869 | ok |
| protected_unauthorized_drop | 3 | 203791 | 201310 | 204139 | 1260 | ok |
| knock_invalid_user_or_key | 3 | 198503 | 194533 | 200036 | 2319 | ok |
| authorized_protected_pass | 3 | 194816 | 193849 | 205495 | 5277 | ok |
| replay_drop | 3 | 20 | 20 | 20 | 0 | ok |
| source_rate_limit | 3 | 138021 | 137156 | 140554 | 1442 | ok |
| active_session_pressure_32 | 3 | 199432 | 186252 | 206259 | 8304 | ok |
| user_scale_128 | 3 | 74060 | 73994 | 75151 | 530 | ok |
| user_scale_1024 | 3 | 73919 | 72380 | 76978 | 1911 | ok |

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
