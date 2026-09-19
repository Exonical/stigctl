# stigctl

`stigctl` is an Enterprise Linux STIG lifecycle CLI. It uses **Yip** for remediation, **Goss** for validation, resolves organizational exceptions, and exports scan results as **CKLB 1.0** for DISA STIG Viewer 3.

The CLI uses Charmbracelet **Fang v2** on top of Cobra.

## Status

The project is under active development. The core baseline resolver, Yip/Goss adapters, exception overlay, XCCDF parser, normalized result model, and CKLB exporter are scaffolded and wired together. STIG rule content still needs to be populated from the authoritative DISA release.

## Requirements

- Go 1.27.1
- [Yip](https://github.com/mudler/yip) on systems where `stigctl apply` is used
- [Goss](https://github.com/goss-org/goss) on systems where `stigctl validate` or `stigctl scan` is used
- The authoritative DISA XCCDF XML for CKLB export

## Commands

```bash
# Discover versioned content
stigctl baseline list
stigctl baseline show rhel9:v2r9

# Apply numbered Yip remediation modules
stigctl apply rhel9:v2r9 --profile server

# Run Goss and resolve rules/exceptions
stigctl validate rhel9:v2r9 --profile server

# Produce a STIG Viewer 3 checklist
stigctl scan rhel9:v2r9 \
  --profile server \
  --format cklb \
  --output host-rhel9-v2r9.cklb

# Raw normalized scan results
stigctl scan rhel9:v2r9 \
  --profile server \
  --format json \
  --output results.json

# Inspect approved exceptions
stigctl exceptions list rhel9:v2r9
stigctl exceptions show rhel9:v2r9 V-XXXXXX
```

Use `--content-root` when the baseline tree is not in the current directory:

```bash
stigctl --content-root /usr/share/stigctl validate rhel9:v2r9
```

## Architecture

```text
                     versioned baseline
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
      rules.yaml     exceptions.yaml   DISA XCCDF
          |                |                |
          +-------+--------+                |
                  |                         |
                  v                         |
              effective policy             |
                  |                         |
       +----------+-----------+             |
       |                      |             |
       v                      v             |
      Yip                    Goss           |
 remediation              validation        |
       |                      |             |
       +----------+-----------+             |
                  |                         |
                  v                         |
          normalized results <--------------+
                  |
             +----+----+
             |         |
             v         v
           CKLB       JSON
```

Yip answers **"make the host compliant."** Goss answers **"what state is the host actually in?"** The policy layer decides applicability and exceptions. The XCCDF remains the authoritative source for STIG checklist metadata.

## Baseline layout

```text
stig/rhel9/v2r9/
├── manifest.yaml
├── rules.yaml
├── exceptions.yaml
├── source/
│   └── <official DISA XCCDF>.xml
├── remediation/
│   ├── 00-packages.yaml
│   ├── 10-kernel.yaml
│   ├── 20-filesystem.yaml
│   ├── 30-ssh.yaml
│   ├── 40-authentication.yaml
│   ├── 50-audit.yaml
│   ├── 60-logging.yaml
│   ├── 70-services.yaml
│   ├── 80-network.yaml
│   └── 90-crypto.yaml
└── validation/
    ├── goss.yaml
    ├── 00-packages.yaml
    ├── 10-kernel.yaml
    ├── 20-filesystem.yaml
    ├── 30-ssh.yaml
    ├── 40-authentication.yaml
    ├── 50-audit.yaml
    ├── 60-logging.yaml
    ├── 70-services.yaml
    ├── 80-network.yaml
    └── 90-crypto.yaml
```

The numbered files are engine configuration. `manifest.yaml`, `rules.yaml`, and `exceptions.yaml` are interpreted by `stigctl`.

## Goss rule identity

Goss tests should be traceable to the DISA V-ID. Prefer explicit metadata:

```yaml
command:
  ssh-root-login:
    title: "V-XXXXXX - Direct root SSH login must be disabled"
    meta:
      stig_id: V-XXXXXX
    exec: "/usr/sbin/sshd -T | grep '^permitrootlogin '"
    exit-status: 0
    stdout:
      - "permitrootlogin no"
```

`stigctl` groups all Goss assertions carrying the same `meta.stig_id` into one normalized STIG rule result.

## Exceptions

Exceptions are kept outside Goss. Goss still measures the technical state; the policy layer overlays the approved exception afterward.

```yaml
schema_version: 1

exceptions:
  V-XXXXXX:
    status: exception

    scope:
      profiles:
        - hpc-compute

    justification:
      reason: "Required for the supported HPC workload."
      impact: "The STIG setting cannot be enabled for this role."
      risk: "Exposure is constrained to the isolated compute environment."

    compensating_controls:
      - "Compute fabric is isolated."
      - "Administrative access is centrally controlled."

    approval:
      ticket: RMF-2026-0042
      owner: platform-security
      approved_by: ISSO
      approved_date: 2026-09-19

    lifecycle:
      created: 2026-09-19
      expires: 2027-03-19
      review_interval_days: 90
```

An exception is **not** treated as a passing technical test.

## Result semantics

Internal results use:

- `pass`
- `fail`
- `skipped`
- `not_applicable`
- `exception`
- `manual`
- `error`

CKLB mapping is intentionally conservative:

| stigctl | CKLB |
|---|---|
| `pass` | `not_a_finding` |
| `fail` | `open` |
| `not_applicable` | `not_applicable` |
| `exception` | `open` with exception details |
| `manual` | `not_reviewed` |
| `skipped` | `not_reviewed` |
| `error` | `not_reviewed` |

## Development

```bash
make tidy
make fmt
make vet
make test
make build
```

The CI workflow uses Go 1.27.1.
