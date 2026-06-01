# FOFA API Threaded Searcher

A powerful multi‑threaded Python tool to query the FOFA (Fofa.so) API, extract selected fields, and save unique results with intelligent formatting.

![Python](https://img.shields.io/badge/python-2.7-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ✨ Features

- **Multi‑threaded** – Fetch multiple pages concurrently (configurable threads)
- **Custom fields** – Choose any valid FOFA field (`ip`, `port`, `title`, `cert.*`, `tls.*`, …)
- **Smart output naming** – Automatically names files based on the primary field (e.g. `domains_*.txt`, `ips_*.txt`)
- **Deduplication** – Avoids duplicate entries across pages and sessions
- **Resume capability** – Loads existing results from a previous run to skip already saved entries
- **Clean formatting** – Human‑readable output with labels, truncation for long values
- **Field validation** – Checks field names before sending the query
- **Interactive CLI** – Guided prompts for query, max pages, and fields (`list` command shows all valid fields)

## 📋 Requirements

- Python 2.7 (the script uses `raw_input` – easily portable to Python 3)
- `requests` library

Install the dependency:

```bash
pip install requests
```

🔧 Configuration

1. Get a FOFA API key
      Register at en.fofa.info and obtain your API key.
2. Set your API key in the script:
      Edit the line
   ```python
   API_KEY = "PUT UR TOKEN HERE"
   ```
   Replace PUT UR TOKEN HERE with your actual key.
   For better security, you can modify the script to read from an environment variable:
   ```python
   import os
   API_KEY = os.getenv("FOFA_API_KEY", "your_default_key")
   ```
3. Adjust other parameters (optional)
      Inside the script you can change:
   · CONCURRENT_THREADS – number of parallel page requests (default 10)
   · SIZE_DEFAULT – results per page, max 100 (default 100)
   · OUTPUT_DIR – directory where output files are saved (default results)

🚀 Usage

Run the script:

```bash
python fofa_searcher.py
```

You will be prompted interactively:

1. Enter FOFA query

```
[?] Enter FOFA query: domain="example.com"
```

2. Max pages to scrape

```
[?] Enter max page to scrape [Default: 1]: 5
```

Each page returns up to SIZE_DEFAULT results.

3. Select output fields

```
[?] Enter fields [Default: host,ip,port]: host,ip,port,title,cert.sn
```

Type list to see all valid fields (basic, certificate, TLS).

4. Output

All results are saved in OUTPUT_DIR with a descriptive filename, e.g.
results/domains_example_com_20250315_143022.txt

📂 Output Examples

Single field – nicely labeled:

```
IP: 93.184.216.34
Port: 443
Title: Example Domain
```

Multiple fields – compact format:

```
93.184.216.34 | Port:443 | [Example Domain] | {US}
```

Certificate / TLS fields – clear labels:

```
Cert Serial Number: 01:23:45:...
TLS version: TLSv1.2
```

🧩 Valid Fields

The tool supports all common FOFA fields plus certificate (cert.*) and TLS (tls.*) fields.

Basic fields (partial list)

ip, port, protocol, base_protocol, host, domain, title, server, country, region, city, os, asn, org, banner, header, body, cname, icp, jarm, icon, fid, status_code, product

Certificate fields

cert, cert.sn, cert.not_after, cert.not_before, cert.domain, cert.subject.org, cert.subject.cn, cert.issuer.org, cert.issuer.cn, cert.is_valid, cert.is_match, cert.is_equal

TLS fields

tls.version, tls.ja3s

Type list during field prompt to see them all.

⚙️ Configuration Variables (inside script)

Variable Default Description
CONCURRENT_THREADS 10 Number of parallel page requests
SIZE_DEFAULT 100 Results per page (max FOFA allows)
OUTPUT_DIR results Directory where output files are saved

📝 Important Notes

· The script uses en.fofa.info as the API endpoint.
· Deduplication is based on the first field value (e.g., IP or domain) and is case‑insensitive.
· Long strings (titles, banners, headers) are truncated in the output for readability.
· If you interrupt the script (Ctrl+C), it exits gracefully.
· The script currently uses Python 2 raw_input. To run with Python 3, replace raw_input with input and adjust the print statements.

❗ Troubleshooting

Issue Solution
API_KEY not set Edit the script and add your key.
Invalid field(s) Run the script and type list to see allowed fields.
No results Check your FOFA query syntax and API credits.
ImportError: No module named requests Install requests with pip install requests.
UnicodeEncodeError The script already handles UTF‑8 encoding; ensure your terminal supports it.

📄 License

MIT License – free to use and modify for your own reconnaissance needs.
Note: FOFA API usage is subject to FOFA’s terms of service.

🙌 Acknowledgements

Built for the FOFA search engine – a powerful IoT and asset search platform.

---

Happy hunting! 🔍

