# SSLInspect

> Version: 1.0.0

**SSLInspect** is a Python-based tool that retrieves and analyzes SSL/TLS certificate information from remote servers. It extracts metadata such as certificate validity, issuer, fingerprints, extensions, and supported ciphers.

## 🔍 Features

- Fetch and parse SSL/TLS certificates from remote hosts
- Display certificate metadata including:
  - Version
  - Serial Number
  - Validity Period
  - Issuer Details
  - SHA-1 and SHA-256 Fingerprints
  - Certificate Extensions
- Detect supported cipher suites via real connection attempts

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- [`cryptography`](https://pypi.org/project/cryptography/)
- [`pydantic`](https://pypi.org/project/pydantic/)

Install required packages:

```bash
pip install -r requirements.txt
```

### Usage

```python
from sslinspect import SSLInspect

obj = SSLInspect("google.com", 443)
print(obj.certificate())
print(obj.certificate().get("ciphers"))

```

## ⚙️ Structure

- `SSLInspect`: Main class for scanning and analyzing the certificate
- `scan()`: Initiates scanning and returns certificate info
- `analyze(cert)`: Parses the certificate object
- `ciphers()`: Attempts cipher negotiation with the server
- `__extensions(cert)`: Parses X.509 extensions

## ⚠️ Disclaimer

- This tool makes real-time connections to remote servers.
- Ensure that you have permission to scan the hosts you target.

## 📄 License

MIT License
