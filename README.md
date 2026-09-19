# stigctl

STIG lifecycle CLI for Enterprise Linux — apply remediations with Yip, validate with Goss, manage exceptions, and export results to CKLB for STIG Viewer.

## CLI

The CLI uses Charmbracelet Fang on top of Cobra for styled help, errors, completions, and manpage support.

```bash
stigctl baseline list
stigctl baseline show rhel9:v2r9

stigctl apply rhel9:v2r9 --profile server
stigctl validate rhel9:v2r9 --profile server

stigctl scan rhel9:v2r9 \
  --profile server \
  --format cklb \
  --output host.cklb

stigctl exceptions list rhel9:v2r9
stigctl exceptions show rhel9:v2r9 V-XXXXXX
```

## Architecture

```text
                stigctl
                   |
      +------------+------------+
      |                         |
      v                         v
     Yip                       Goss
 remediation                validation
      |                         |
      +------------+------------+
                   |
                   v
          normalized results
                   |
             +-----+-----+
             |           |
             v           v
            CKLB        JSON
```

## Layout

```text
cmd/stigctl/                 CLI entrypoint
internal/cli/                Fang/Cobra commands
internal/remediation/        remediation interfaces/adapters
internal/validation/         validation interfaces/adapters
internal/results/            normalized result model
internal/export/             result exporters
stig/<product>/<release>/    versioned STIG content
```
