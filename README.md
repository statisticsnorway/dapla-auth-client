# Dapla Auth Client

[![PyPI](https://img.shields.io/pypi/v/dapla-auth-client.svg)][pypi status]
[![Status](https://img.shields.io/pypi/status/dapla-auth-client.svg)][pypi status]
[![Python Version](https://img.shields.io/pypi/pyversions/dapla-auth-client)][pypi status]
[![License](https://img.shields.io/pypi/l/dapla-auth-client)][license]

[![Documentation](https://github.com/statisticsnorway/dapla-auth-client/actions/workflows/docs.yml/badge.svg)][documentation]
[![Tests](https://github.com/statisticsnorway/dapla-auth-client/actions/workflows/tests.yml/badge.svg)][tests]
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=statisticsnorway_dapla-auth-client&metric=coverage)][sonarcov]
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=statisticsnorway_dapla-auth-client&metric=alert_status)][sonarquality]

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)][pre-commit]
[![Black](https://img.shields.io/badge/code%20style-black-000000.svg)][black]
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)][poetry]

[pypi status]: https://pypi.org/project/dapla-auth-client/
[documentation]: https://statisticsnorway.github.io/dapla-auth-client
[tests]: https://github.com/statisticsnorway/dapla-auth-client/actions?workflow=Tests
[sonarcov]: https://sonarcloud.io/summary/overall?id=statisticsnorway_dapla-auth-client
[sonarquality]: https://sonarcloud.io/summary/overall?id=statisticsnorway_dapla-auth-client
[pre-commit]: https://github.com/pre-commit/pre-commit
[black]: https://github.com/psf/black
[poetry]: https://python-poetry.org/

## Features

- Detects Dapla environment, service, and region via environment variables
- Retrieves current Dapla region (e.g., checks for DAPLA_LAB)
- Reads Kubernetes service-account token from filesystem
- Exchanges Kubernetes token for Keycloak token in Dapla Lab
- Overrides Google-Auth refresh handler to use custom token fetch logic
- Fetches Google ADC credentials

## Requirements

- Python >3.8 (3.10 is preferred)
- Poetry, install via curl -sSL https://install.python-poetry.org | python3 -

## Installation

You can install _Dapla Auth Client_ via [pip] from [PyPI]:

```console
pip install dapla-auth-client
```

## Usage

```python
# This code snippet demonstrates how to use the Dapla Auth Client to fetch a personal token.

from dapla_auth_client import AuthClient

print(AuthClient.fetch_personal_token())
```

## Contributing

Contributions are very welcome.
To learn more, see the [Contributor Guide].

## License

Distributed under the terms of the [MIT license][license],
_Dapla Auth Client_ is free and open source software.

## Issues

If you encounter any problems,
please [file an issue] along with a detailed description.

## Credits

This project was generated from [Statistics Norway]'s [SSB PyPI Template].

[statistics norway]: https://www.ssb.no/en
[pypi]: https://pypi.org/
[ssb pypi template]: https://github.com/statisticsnorway/ssb-pypitemplate
[file an issue]: https://github.com/statisticsnorway/dapla-auth-client/issues
[pip]: https://pip.pypa.io/

<!-- github-only -->

[license]: https://github.com/statisticsnorway/dapla-auth-client/blob/main/LICENSE
[contributor guide]: https://github.com/statisticsnorway/dapla-auth-client/blob/main/CONTRIBUTING.md
[reference guide]: https://statisticsnorway.github.io/dapla-auth-client/reference.html
