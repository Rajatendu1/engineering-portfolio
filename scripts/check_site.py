#!/usr/bin/env python3
"""Offline structural and security checks, not visual or remote availability tests."""
import argparse
import base64
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit

class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.tags, self.ids, self.scripts = [], [], []
        self.current_script = None
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if 'id' in attrs:
            self.ids.append(attrs['id'])
        if tag == 'script':
            if 'src' in attrs:
                raise ValueError('External scripts are not allowed')
            self.current_script = ''
    def handle_data(self, data):
        if self.current_script is not None:
            self.current_script += data
    def handle_endtag(self, tag):
        if tag == 'script' and self.current_script is not None:
            self.scripts.append(self.current_script)
            self.current_script = None

def check(root):
    required = ['index.html', 'style.css', 'favicon.svg', 'og.png', 'vercel.json']
    for name in required:
        if not (root / name).is_file():
            raise ValueError('Missing required file: ' + name)
    if (root / 'og.png').read_bytes()[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('og.png is not a PNG')
    page = Page()
    page.feed((root / 'index.html').read_text())
    if len(page.ids) != len(set(page.ids)):
        raise ValueError('Duplicate HTML ids')
    if len(page.scripts) != 1:
        raise ValueError('Expected one inline script')
    for tag, attrs in page.tags:
        if attrs.get('target') == '_blank' and 'noopener' not in attrs.get('rel', '').split():
            raise ValueError('New-tab link missing noopener')
        for key in ['href', 'src']:
            value = attrs.get(key)
            if not value:
                continue
            url = urlsplit(value)
            if url.scheme:
                if url.scheme not in {'https', 'mailto', 'tel', 'data'}:
                    raise ValueError('Unsafe URL scheme: ' + url.scheme)
                continue
            if url.netloc:
                raise ValueError('Protocol-relative URL')
            if url.path:
                asset = (root / unquote(url.path).lstrip('/')).resolve()
                if not asset.is_relative_to(root.resolve()) or not asset.is_file():
                    raise ValueError('Missing or escaping local asset: ' + value)
            if url.fragment and not url.path and unquote(url.fragment) not in page.ids:
                raise ValueError('Missing local anchor: ' + value)
    config = json.loads((root / 'vercel.json').read_text())
    blocks = [x for x in config.get('headers', []) if x.get('source') == '/(.*)']
    if len(blocks) != 1:
        raise ValueError('Expected one all-path security header block')
    headers = {x['key'].lower(): x['value'] for x in blocks[0]['headers']}
    expected = {
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    }
    for key, value in expected.items():
        if headers.get(key) != value:
            raise ValueError('Security header mismatch: ' + key)
    csp = dict(part.strip().split(' ', 1) if ' ' in part.strip() else (part.strip(), '')
               for part in headers.get('content-security-policy', '').split(';') if part.strip())
    digest = base64.b64encode(hashlib.sha256(page.scripts[0].encode()).digest()).decode()
    if csp.get('script-src') != "'sha256-" + digest + "'":
        raise ValueError('Inline script CSP hash mismatch')
    for directive, value in [('default-src', "'none'"), ('connect-src', "'none'"),
                             ('object-src', "'none'"), ('base-uri', "'none'"),
                             ('form-action', "'none'"), ('frame-ancestors', "'none'")]:
        if csp.get(directive) != value:
            raise ValueError('CSP directive mismatch: ' + directive)
    with tempfile.TemporaryDirectory() as temp:
        script = Path(temp) / 'inline.js'
        script.write_text(page.scripts[0])
        result = subprocess.run(['node', '--check', str(script)], capture_output=True, text=True)
        if result.returncode:
            raise ValueError('Inline JavaScript syntax failed')
    return True

def self_test(root):
    mutations = {
        'missing asset': lambda p: (p / 'style.css').unlink(),
        'missing anchor': lambda p: edit(p, 'index.html', 'href="#projects"', 'href="#missing-gate-anchor"'),
        'duplicate id': lambda p: edit(p, 'index.html', '</body>', '<div id="top"></div></body>'),
        'new-tab protection': lambda p: edit(p, 'index.html', 'rel="noopener"', 'rel=""'),
        'CSP hash': lambda p: edit(p, 'index.html', "(function(){", "(function(){\n// changed\n"),
        'security header': lambda p: edit(p, 'vercel.json', 'nosniff', 'unsafe'),
        'unsafe link': lambda p: edit(p, 'index.html', 'href="#projects"', 'href="javascript:alert(1)"'),
        'external script': lambda p: edit(p, 'index.html', '<script>', '<script src="https://example.invalid/a.js">'),
    }
    for name, mutate in mutations.items():
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp)
            for f in ['index.html', 'style.css', 'favicon.svg', 'og.png', 'vercel.json']:
                shutil.copyfile(root / f, dest / f)
            mutate(dest)
            try:
                check(dest)
            except ValueError:
                print('Rejected:', name)
            else:
                raise AssertionError('Negative regression did not fail: ' + name)
    print('NEGATIVE CHECKS PASS:', len(mutations))

def edit(root, name, before, after):
    p = root / name
    content = p.read_text()
    if before not in content:
        raise AssertionError('Mutation target missing: ' + before)
    p.write_text(content.replace(before, after, 1))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    if args.self_test:
        self_test(root)
    else:
        check(root)
        print('STATIC SITE CHECKS PASS (offline, not visual or remote availability tests)')
