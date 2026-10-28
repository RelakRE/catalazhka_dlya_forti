"""Audit the explicit public export, never upload files or print matching secrets."""
from pathlib import Path
import argparse
import ipaddress
import json
import re
import sys

EXCLUDED = {'.git', 'bin', 'obj', 'build', 'private', '__pycache__'}
TEXT = {'.cs', '.csproj', '.ps1', '.js', '.py', '.md', '.json', '.cmd', '.yml', '.yaml', '.txt'}
DOC_NETS = tuple(ipaddress.ip_network(x) for x in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'))

def inspect(root: Path, deny=()):
    findings = []
    files = 0
    for path in sorted(root.rglob('*')):
        if any(part in EXCLUDED for part in path.relative_to(root).parts):
            continue
        relative = str(path.relative_to(root))
        if path.is_symlink():
            findings.append((relative, 'symlink')); continue
        if not path.is_file():
            continue
        files += 1
        if path.suffix.lower() in {'.exe', '.dll', '.zip', '.rdp', '.pfx', '.p12', '.key', '.log', '.sqlite', '.db', '.etl', '.ndjson', '.pem'} or path.name.endswith('.local.json'):
            findings.append((relative, 'private-or-binary-artifact'))
        data = path.read_bytes()
        for value in deny:
            if value and (value.lower().encode() in data.lower() or value.lower().encode('utf-16-le') in data.lower()):
                findings.append((relative, 'private-fingerprint'))
        if path.suffix.lower() not in TEXT and path.name not in {'.gitignore', 'LICENSE'}:
            continue
        text = data.decode('utf-8-sig', errors='replace')
        if re.search(r'[A-Za-z]:[\\/]+Users[\\/]+(?!<|\*|\$|%)[A-Za-z0-9 _-]+', text):
            findings.append((relative, 'personal-home-path'))
        if re.search(r'"(?:password|passwd|otp|cookie|token|client_secret)"\s*:\s*"[^"\r\n]{3,}"', text, re.I):
            findings.append((relative, 'plaintext-secret-field'))
        if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16}', text):
            findings.append((relative, 'secret-shaped-value'))
        for match in re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', text):
            try:
                ip = ipaddress.ip_address(match)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified or any(ip in net for net in DOC_NETS) or (path.name == "audit_public.py" and match in {"10.0.0.0", "172.16.0.0", "192.168.0.0"}):
                continue
            if ip in ipaddress.ip_network('10.0.0.0/8') or ip in ipaddress.ip_network('172.16.0.0/12') or ip in ipaddress.ip_network('192.168.0.0/16'):
                findings.append((relative, 'non-documentation-private-ip'))
    return {'files_scanned': files, 'passed': not findings, 'findings': [{'file': p, 'kind': k} for p, k in sorted(set(findings))]}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('--denylist', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = inspect(args.directory, json.loads(args.denylist.read_text(encoding='utf-8-sig')) if args.denylist else ())
    if args.output:
        args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result['passed'] else 1

if __name__ == '__main__':
    sys.exit(main())
