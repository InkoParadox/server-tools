# Diagnostics

Standalone Bash utilities. These files are separate from the unchanged IPv6 transaction tool 2.3.1.

- `ssh-check.sh`: read-only SSH configuration/socket inspection, including systemd-owned listeners. No remote login proof.
- `ipv6-check.sh`: sysctl on all/default/lo and interfaces, global addresses and default routes. Runtime overview, not persistence/transaction acceptance.
- `cpu-steal.sh`: passive 60-second vmstat sampling; no stress load. Missing data and vmstat failures return nonzero. Thresholds are diagnostic heuristics.
- `ip-geolocation.sh`: the owner's former Gist geo script, now directly downloaded and checked instead of an eval/pipe bootstrap. Requires curl/jq/ip/timeout and Bash. Interface IPv4 addresses excluding RFC1918 are inspected; NAT discovery is not claimed. No-data results fail.
- `ipregion.sh`: small launcher for Davoyan/ipregion at commit e2c6c83bdc90010d13bc5f9c747e3b77fa660791 with SHA-256 verification. The third-party project and its embedded values are not vendored here.
- `network-bench.sh`: adapter for bench.tlab.pw/bench.sh frozen by SHA-256 a02ff383bdb96dea984cb4f2feea77caac383070d4bbd37b088f3ebd0ac38853. Uses an existing iperf3 or downloads the correct amd64/arm64v8 asset from userdocs/iperf3-static 3.22 with its published SHA-256. Upstream sees the checked binary in PATH, avoiding its obsolete ARM64 fallback. The benchmark is not copied into this repository.

All download errors, checksum mismatches and syntax failures stop before execution. Mutable benchmark endpoint changes fail closed and require a reviewed hash update. Each file is independent so it can be downloaded on its own. No Xshell export, private infrastructure configuration or credentials belong here.

Focused local fixtures for the Xshell V1 bundle checked failure propagation, socket activation, IPv6 addresses and CPU no-data handling. They do not prove native Linux behavior, VPS connectivity or Xshell Send String. Publication in draft is preparation only; main requires the owner's separate approval.
