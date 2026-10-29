#!/usr/bin/env python3
"""Build and encrypt the Call Copilot notes pack.

Usage:
  NOTES_PASSPHRASE=... python3 tools/notes_pack.py MEMORY_DIR [OUT_JSON]

MEMORY_DIR mirrors the Claude memory store's /projects tree:
  MEMORY_DIR/projects/<project-id>/<file>.md   (subfolders allowed)

Writes OUT_JSON (default: notes.enc.json in the repo root) only when the
notes changed since the last published copy. Prints "unchanged" or "updated".
"""
import base64, datetime, hashlib, hmac, json, os, re, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 600_000
NAMES = {  # project id prefix -> folder/toggle name
    '01997cfd': 'Job Search & Networking', '019bba88': 'Modern Data Management',
    '019c0762': 'International Management Capstone', '019cf7ba': 'Operations Strategy',
    '019d0729': 'Big Data', '019d2a8f': 'Pricing Strategy', '019ea851': 'NASCO',
    '019f6bff': 'HCSC LDP', '019fd986': 'IDC', '01a0349d': 'Swish House',
    '01a0c9d4': 'Entrepreneurship & Passive Income', '01a0d565': 'Nora',
    '01a10e0f': 'Untitled project',
}


def split_front(text):
    m = re.match(r'\s*---\n(.*?)\n---\n?', text, re.S)
    return (m.group(1), text[m.end():]) if m else ('', text)


def field(front, key):
    m = re.search(rf'^{key}:\s*"?(.*?)"?\s*$', front, re.M)
    return m.group(1) if m else ''


def project_name(pid, pdir):
    if pid[:8] in NAMES:
        return NAMES[pid[:8]]
    idx = os.path.join(pdir, 'index.md')
    if os.path.exists(idx):
        n = field(split_front(open(idx, encoding='utf-8').read())[0], 'name')
        n = re.sub(r'[\\/:*?"<>|]', '', n).strip()
        if n:
            return n
    return 'Project ' + pid[:8]


def render(proj, rel, text):
    front, body = split_front(re.sub(r'^\[updated:.*$', '', text, flags=re.M))
    body = re.sub(r'\[(stated|observed|inferred)\] ', '', body)
    body = re.sub(r'\[\[([^\]]+)\]\]', r'\1', body)
    title = rel[:-3].replace('/', ' — ').replace('-', ' ').title()
    return f'# {proj}: {title}\n\n_{field(front, "description")}_\n\n{body.strip()}\n'


def build(mem_dir):
    root = os.path.join(mem_dir, 'projects')
    projects = {}
    for pid in sorted(os.listdir(root)):
        pdir = os.path.join(root, pid)
        if not os.path.isdir(pdir):
            continue
        name = project_name(pid, pdir)
        docs = []
        for dp, _, fs in os.walk(pdir):
            for f in fs:
                if f.endswith('.md'):
                    rel = os.path.relpath(os.path.join(dp, f), pdir).replace(os.sep, '/')
                    docs.append((rel, open(os.path.join(dp, f), encoding='utf-8').read()))
        order = lambda r: ({'overview.md': 0, 'index.md': 1}.get(r, 9), r)
        docs.sort(key=lambda d: order(d[0]))
        projects[name] = '\n\n---\n\n'.join(render(name, r, t).strip() for r, t in docs)
    return ''.join(f'<!-- project: {n} -->\n{projects[n]}\n\n' for n in sorted(projects))


def encrypt(plain, passphrase):
    salt, nonce = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(passphrase.encode())
    ct = AESGCM(key).encrypt(nonce, plain.encode(), None)
    b64 = lambda b: base64.b64encode(b).decode()
    return {'v': 1, 'kdf': {'name': 'PBKDF2', 'hash': 'SHA-256', 'iterations': ITERATIONS, 'salt': b64(salt)},
            'cipher': 'AES-GCM', 'nonce': b64(nonce), 'ct': b64(ct)}


def build_docs(doc_dir, project):
    """Project documents (e.g. HCSC Live Context) -> one pack, one marker per document."""
    out = []
    for dp, _, fs in os.walk(doc_dir):
        for f in sorted(fs):
            path = os.path.join(dp, f)
            rel = os.path.relpath(path, doc_dir).replace(os.sep, '/')
            try:
                text = open(path, encoding='utf-8').read().strip()
            except UnicodeDecodeError:
                continue
            if text:
                out.append(f'<!-- doc: {project} | {rel} -->\n{text}\n\n')
    return ''.join(sorted(out))


def main():
    args = sys.argv[1:]
    passphrase = os.environ.get('NOTES_PASSPHRASE', '')
    if len(passphrase) < 20:
        sys.exit('NOTES_PASSPHRASE missing or too short')
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
    if args and args[0] == '--docs':
        # notes_pack.py --docs DOC_DIR "Project name" [OUT_JSON]
        doc_dir, project = args[1], args[2]
        out = args[3] if len(args) > 3 else os.path.join(root, 'docs-' + re.sub(r'[^a-z0-9]+', '-', project.lower()).strip('-') + '.enc.json')
        plain = build_docs(doc_dir, project)
        if not plain:
            sys.exit('no documents found under ' + doc_dir)
        count = plain.count('<!-- doc:')
    else:
        mem_dir = args[0]
        out = args[1] if len(args) > 1 else os.path.join(root, 'notes.enc.json')
        plain = build(mem_dir)
        if plain.count('<!-- project:') == 0:
            sys.exit('no projects found under ' + mem_dir)
        count = plain.count('<!-- project:')
    _write(plain, passphrase, out, count)


def _write(plain, passphrase, out, count):
    # change marker keyed by the passphrase, so it reveals nothing about the notes
    tag = hmac.new(passphrase.encode(), plain.encode(), hashlib.sha256).hexdigest()
    if os.path.exists(out):
        try:
            if json.load(open(out)).get('tag') == tag:
                print('unchanged'); return
        except Exception:
            pass
    doc = encrypt(plain, passphrase)
    doc['tag'] = tag
    doc['generated'] = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    doc['items'] = count
    with open(out, 'w') as f:
        json.dump(doc, f)
    # keep a list of published packs so the page knows what to fetch
    manifest = os.path.join(os.path.dirname(os.path.abspath(out)), 'packs.json')
    try:
        names = json.load(open(manifest))
    except Exception:
        names = ['notes.enc.json']
    if os.path.basename(out) not in names:
        names.append(os.path.basename(out))
        with open(manifest, 'w') as f:
            json.dump(names, f)
    print('updated', count, 'items')


if __name__ == '__main__':
    main()
