# Third-party attributions

SlowShield is built on these open-source projects. Thank you to their authors and maintainers.

## Python runtime dependencies

| Package | Version | License | Project |
|---|---|---|---|
| anyio | 4.15.1 | MIT | [link](https://github.com/agronholm/anyio) |
| certifi | 2026.7.22 | Mozilla Public License 2.0 (MPL 2.0) | [link](https://github.com/certifi/python-certifi) |
| charset-normalizer | 3.5.1 | MIT |  |
| click | 8.5.0 | BSD-3-Clause | [link](https://github.com/pallets/click/) |
| googleapis-common-protos | 1.75.3 | Apache-2.0 | [link](https://github.com/googleapis/google-cloud-python/tree/main/packages/googleapis-common-protos) |
| granian | 2.8.3 | BSD License | [link](https://github.com/emmett-framework/granian) |
| idna | 3.20 | BSD-3-Clause | [link](https://github.com/kjd/idna) |
| Jinja2 | 3.1.6 | BSD License | [link](https://github.com/pallets/jinja/) |
| markdown-it-py | 4.2.0 | MIT License | [link](https://github.com/executablebooks/markdown-it-py) |
| MarkupSafe | 3.0.3 | BSD-3-Clause | [link](https://github.com/pallets/markupsafe/) |
| mdurl | 0.1.2 | MIT License | [link](https://github.com/executablebooks/mdurl) |
| msgspec | 0.21.1 | BSD-3-Clause | [link](https://jcristharif.com/msgspec/) |
| opentelemetry-api | 1.44.0 | Apache-2.0 | [link](https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-api) |
| opentelemetry-exporter-otlp-proto-common | 1.44.0 | Apache-2.0 | [link](https://github.com/open-telemetry/opentelemetry-python/tree/main/exporter/opentelemetry-exporter-otlp-proto-common) |
| opentelemetry-exporter-otlp-proto-http | 1.44.0 | Apache-2.0 | [link](https://github.com/open-telemetry/opentelemetry-python/tree/main/exporter/opentelemetry-exporter-otlp-proto-http) |
| opentelemetry-proto | 1.44.0 | Apache-2.0 | [link](https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-proto) |
| opentelemetry-sdk | 1.44.0 | Apache-2.0 | [link](https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-sdk) |
| opentelemetry-semantic-conventions | 0.65b0 | Apache-2.0 | [link](https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-semantic-conventions) |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | [link](https://github.com/pypa/packaging) |
| protobuf | 7.36.2 | 3-Clause BSD License | [link](https://developers.google.com/protocol-buffers/) |
| pyreqwest | 0.13.0 | see project | [link](https://github.com/MarkusSintonen/pyreqwest) |
| python-dotenv | 1.2.3 | BSD-3-Clause | [link](https://github.com/theskumar/python-dotenv) |
| requests | 2.34.2 | Apache Software License | [link](https://github.com/psf/requests) |
| starlette | 1.7.0 | BSD-3-Clause | [link](https://github.com/Kludex/starlette) |
| typing_extensions | 4.16.0 | PSF-2.0 | [link](https://github.com/python/typing_extensions) |
| urllib3 | 2.8.0 | MIT |  |
| uvloop | 0.22.1 | Apache Software License, MIT License |  |

## Threat-intelligence data

| Source | Used for | Terms |
|---|---|---|
| [OSV](https://osv.dev/) | Malicious-package advisories (`MAL-*`) for PyPI, npm, Go and Maven | [CC-BY-4.0](https://github.com/google/osv.dev/blob/master/LICENSE) |
| [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) | Origin of the `MAL-*` records OSV redistributes | [Apache-2.0](https://github.com/ossf/malicious-packages/blob/main/LICENSE) |
| [GitHub Advisory Database](https://github.com/advisories) | `malware` advisories via the REST API | [CC-BY-4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md) |

## Bundled front-end assets

| Asset | License |
|---|---|
| [htmx](https://htmx.org/) 4.x (`ui/static/vendor/htmx.min.js`) | 0BSD |

## Container images

Built on [Amazon Linux 2023](https://aws.amazon.com/linux/amazon-linux-2023/) packages (see each RPM's license
in the image's RPM database), [python-build-standalone](https://github.com/astral-sh/python-build-standalone)
CPython 3.15 (PSF-2.0 and bundled third-party licenses) and [Caddy](https://caddyserver.com/) (Apache-2.0).

