# Password Scanner / Secret Scanner
```bash
WARNING: Only scan systems/files you own or are authorized to test.
```
Local-only CLI to scan files (text, .docx, .pdf) for tokens, keys & passwords.
**Use only on systems/files you own or are authorized to test.**

## Quickstart
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 password_scanner.py ./testdata --config config.yml


