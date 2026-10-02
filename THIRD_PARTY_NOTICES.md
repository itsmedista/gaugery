# Third-party software

Gaugery is licensed under the GNU AGPL v3 (see [LICENSE](LICENSE)). It uses the following
software, each under its own license. All of them can be combined with the AGPL.

## Bundled in this repository

| Component | License | Where |
|---|---|---|
| IBM Plex Sans and IBM Plex Mono fonts, © 2019 IBM Corp. | SIL Open Font License 1.1 | `static/fonts/`, license in [`static/fonts/OFL.txt`](static/fonts/OFL.txt) |

## Python packages, installed from PyPI at build time

Versions and hashes are locked in [`requirements.txt`](requirements.txt).

| Package | License |
|---|---|
| fastapi | MIT |
| starlette | BSD-3-Clause |
| uvicorn | BSD-3-Clause |
| httpx, httpcore | BSD-3-Clause |
| h11 | MIT |
| anyio | MIT |
| idna | BSD-3-Clause |
| certifi | MPL-2.0 |
| psutil | BSD-3-Clause |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| cffi | MIT-0 |
| pycparser | BSD-3-Clause |
| pydantic, pydantic-core | MIT |
| annotated-types, annotated-doc, typing-inspection | MIT |
| typing-extensions | PSF-2.0 |
| click | BSD-3-Clause |

certifi is used unmodified. Its source, under the MPL-2.0, is at
<https://github.com/certifi/python-certifi>.

## Container images pulled by the Docker setup

Gaugery's repository contains no copies of these images. Docker downloads them from Docker Hub
when you install.

| Image | License |
|---|---|
| `python:3.12-slim`: Debian and CPython, the base of Gaugery's own image | CPython under the PSF License. Debian packages under their own licenses (GPL, LGPL, MIT and others), listed in `/usr/share/doc/*/copyright` in the image |
| `tecnativa/docker-socket-proxy` | Apache-2.0 (includes HAProxy, GPL-2.0) |

If you **publish a built Gaugery image** (for example to a registry), you are distributing
those Debian packages too. Their GPL and LGPL terms then require you to offer their source,
for example by pointing to Debian's archive for the exact package versions.
