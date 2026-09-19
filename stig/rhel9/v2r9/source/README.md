# Authoritative STIG source

Place the official DISA RHEL 9 V2R9 XCCDF XML in this directory.

`stigctl scan --format cklb` parses the XCCDF to populate STIG Viewer 3 metadata such as benchmark and rule identifiers, titles, severities, check text, fix text, CCIs, and release information.

The XCCDF is intentionally kept separate from the Yip remediation and Goss validation content.
