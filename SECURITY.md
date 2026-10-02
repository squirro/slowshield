# Security policy

SlowShield is security infrastructure; we take reports seriously and appreciate coordinated disclosure.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") on this repository with a description, affected version(s),
and reproduction steps.

We acknowledge reports within 3 business days, keep you informed while we work on a fix, and credit you in
the release notes unless you prefer otherwise.

## Supported versions

Only the latest minor release receives security fixes. Container images are rebuilt when the Amazon Linux
2023 base or a dependency publishes a security update.

## Scope

In scope: the proxy (policy bypasses, cache poisoning, request smuggling, SSRF/open proxy, path traversal,
integrity/tamper-detection bypasses, XSS or other issues in the UI), the container images, the deployment
examples and the CI/CD workflows of this repository.

Out of scope: vulnerabilities in packages *served* by SlowShield (report those to the package owners or the
OpenSSF malicious-packages project), and denial of service requiring unrealistic traffic volumes.
