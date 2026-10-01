# Security Model

LPET is intentionally designed as a **detection-only** scanner.

It must not:
- execute discovered SUID binaries
- attempt command injection or shell escapes
- alter permissions/ownership
- modify cron or systemd configuration
- create persistence
- extract credentials
- attempt to obtain a root shell

The scanner may execute standard enumeration utilities in read-only mode. Run it only on systems
you own or have explicit authorization to assess.

## False positives
All findings should be manually validated. A SUID binary, sudo rule, capability, service path,
or old kernel branch is not automatically exploitable.
