# stigctl

`stigctl` is an Enterprise Linux STIG lifecycle CLI. **Yip and Goss are compiled directly into the `stigctl` binary**: Yip provides remediation, Goss provides validation, the policy layer resolves organizational exceptions, and scan results can be exported as **CKLB 1.0** for DISA STIG Viewer 3.

The CLI uses Charmbracelet **Fang v2** on top of Cobra.

## Status

The project is under active development. The core baseline resolver, Yip/Goss adapters, exception overlay, XCCDF parser, normalized result model, and CKLB exporter are scaffolded and wired together. STIG rule content still needs to be populated from the authoritative DISA release.

## Runtime dependencies

`stigctl` does **not** require separate `yip` or `goss` executables. Both engines are linked into the Go binary. Host utilities referenced by STIG checks/remediations (for example `systemctl`, `sysctl`, `dnf`, `sshd`, or `auditctl`) are still expected to come from the target operating system.

For development:

- Go 1.27.1
- The authoritative DISA XCCDF XML for CKLB export

## Commands

```bash
# Discover versioned content
stigctl baseline list
stigctl baseline show rhel9:v2r9

# Import an official DISA STIG ZIP and sync rules.yaml
stigctl baseline import rhel9:v2r9 U_RHEL_9_V2R9_STIG.zip

# Optionally import a clean STIG Viewer 3 CKLB as the exact export template
stigctl baseline import-cklb rhel9:v2r9 RHEL_9_Dev.cklb

# Verify XCCDF, rules.yaml, and CKLB metadata stay aligned
stigctl baseline verify rhel9:v2r9

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

# JUnit XML for GitLab, GitHub Actions, Jenkins, and other CI systems
stigctl scan rhel9:v2r9 \
  --profile server \
  --format junit \
  --output results.xml \
  --fail-on-findings

# Produce CKLB and JUnit from the same scan
stigctl scan rhel9:v2r9 \
  --profile server \
  --format cklb \
  --output results.cklb \
  --junit-output results.xml \
  --fail-on-findings

# Scan an SSH inventory in parallel
stigctl scan rhel9:v2r9 \
  --inventory inventory.yaml \
  --format cklb \
  --output ./results

# Inspect approved exceptions
stigctl exceptions list rhel9:v2r9
stigctl exceptions show rhel9:v2r9 V-XXXXXX
```

Use `--content-root` when the baseline tree is not in the current directory:

```bash
stigctl --content-root /usr/share/stigctl validate rhel9:v2r9
```

## Remote inventory scanning

`scan --inventory` scans Linux hosts over SSH without requiring `stigctl`, Goss,
or baseline content to already be installed on them. The controller stages the
current `stigctl` executable and the selected baseline in a temporary directory,
runs the scan on the target, downloads the CKLB or JSON result, and removes the
temporary files.

```yaml
version: 1

defaults:
  user: stigscanner
  port: 22
  identity_file: ~/.ssh/stigscanner_ed25519
  known_hosts_file: ~/.ssh/known_hosts
  profile: server
  sudo: true

hosts:
  - name: compute-01
    address: 10.20.30.41
    hostname: compute-01.example.internal
    ip_address: 10.20.30.41

  - name: compute-02
    address: 10.20.30.42
    sudo: false
    role: Member Server
    comments: Scanned by the infrastructure compliance pipeline
```

Run the inventory with up to eight concurrent SSH sessions:

```bash
stigctl scan rhel9:v2r9 \
  --inventory inventory.yaml \
  --concurrency 8 \
  --format cklb \
  --output ./results \
  --fail-on-findings
```

The output directory receives one artifact per inventory name, such as
`results/compute-01-rhel9-v2r9.cklb`. A result is still downloaded when
`--fail-on-findings` makes the remote scan exit nonzero.

Use `--format junit` to write one XML report per inventory host. Each STIG rule
is represented as a JUnit testcase: open findings are failures, validation
errors are errors, and manual/not-applicable/exception/skipped rules are marked
skipped. For example, `compute-01-rhel9-v2r9.xml` can be published directly as
a GitLab `artifacts:reports:junit` report or consumed by another JUnit-aware CI
test reporter.

To collect both formats from an SSH inventory without running validation twice,
keep CKLB as the primary format and provide a JUnit output directory:

```bash
stigctl scan rhel9:v2r9 \
  --inventory inventory.yaml \
  --format cklb \
  --output ./cklb-results \
  --junit-output ./junit-results \
  --fail-on-findings
```

For GitLab CI, retain the report even when findings make the scan job fail:

```yaml
stig-scan:
  script:
    - ./stigctl scan rhel9:v2r9 --profile server --format junit --output stig-results.xml --fail-on-findings
  artifacts:
    when: always
    reports:
      junit: stig-results.xml
```

Remote scanning uses the system OpenSSH `ssh` and `scp` clients. Authentication
is noninteractive (`BatchMode=yes`) and uses the specified private key, the SSH
agent, or normal OpenSSH configuration. Host-key verification is always enabled;
unknown hosts must be enrolled in `known_hosts` before scanning.

When `sudo: true`, the remote command is prefixed with `sudo -n --`. This avoids
root SSH login and prevents a CI job from waiting for an interactive password.
The SSH account must therefore already be trusted for noninteractive sudo. Since
the account can upload and run the transient executable, granting sudo for that
path is equivalent to granting root execution; do not treat a wildcard sudoers
rule for `/var/tmp/stigctl-remote.*` as narrowly scoped access. If `sudo: false`,
checks that need privileged access may fail.

The staged executable must be compatible with the target operating system and
CPU architecture. Temporary data is created under `/var/tmp` and removed after
the result is collected.

### Windows controller

Baseline, profile, and exception commands run natively on Windows. Local
remediation and validation require Linux because the embedded Yip and Goss
engines use Linux system interfaces.

A Windows machine can still control agentless inventory scans. Supply a Linux
`stigctl` executable compatible with the target hosts using `--remote-binary`:

```powershell
go run .\cmd\stigctl\main.go scan rhel9:v2r9 `
  --inventory .\inventory.yaml `
  --remote-binary .\stigctl-linux-amd64 `
  --format cklb `
  --output .\cklb-results `
  --junit-output .\junit-results
```

The controller uses the system `ssh.exe` and `scp.exe` clients. The remote
Linux hosts do not need `stigctl`, Goss, or baseline content installed; the
controller stages them temporarily and removes them after each scan.

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
│   ├── <official DISA XCCDF>.xml
│   └── template.cklb              # optional, sanitized STIG Viewer 3 template
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

## Authoritative baseline import

The preferred baseline bootstrap is the official DISA release ZIP:

```bash
stigctl baseline import rhel9:v2r9 U_RHEL_9_V2R9_STIG.zip
```

`stigctl` extracts the XCCDF, validates the release against the manifest, and refreshes `rules.yaml` while preserving implementation metadata such as remediation and validation mappings.

A STIG Viewer 3 CKLB can also be imported as an exact export template:

```bash
stigctl baseline import-cklb rhel9:v2r9 RHEL_9_Dev.cklb
```

The imported checklist is validated against the XCCDF when available and sanitized before it is stored: target host data, findings, comments, statuses, and overrides are cleared while STIG/rule UUIDs and official checklist metadata are preserved.

When `template.cklb` exists, `stigctl scan --format cklb` overlays Goss results onto that template. Otherwise, it builds a CKLB from the XCCDF. A one-off template can also be supplied with `--cklb-template`.

```bash
stigctl scan rhel9:v2r9 \
  --profile server \
  --cklb-template ./RHEL_9_Dev.cklb \
  --format cklb \
  -o node01.cklb
```

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


## Releases

Releases are built with GoReleaser. The release artifacts are Linux `amd64` and `arm64` archives containing the `stigctl` binary plus the versioned STIG content, profiles, schemas, license, and README.

Validate the release configuration locally with:

```bash
make release-check
```

Create a local snapshot without publishing:

```bash
make snapshot
```

Published releases use semantic version tags such as `v0.0.1`. The GitHub release workflow is pinned to GoReleaser v2.18.2 and refuses to publish unless GitHub immutable releases are enabled for the repository.

Enable release immutability in **Repository Settings → Releases → Enable release immutability** before creating the first release. Once an immutable release is published, GitHub locks its tag and assets and generates a release attestation.

The CI workflow will create the initial `v0.0.1` tag automatically after tests pass only when immutable releases are enabled. Subsequent releases should be created with new semantic-version tags; published release tags must never be reused or moved.
