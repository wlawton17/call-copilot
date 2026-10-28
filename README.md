# call-copilot

Live call assistant for a phone: listens through the mic, labels who's speaking, and suggests what to say, grounded in your own notes.

- `index.html`: the page (served by GitHub Pages).
- `notes.enc.json`: project notes, AES-256-GCM encrypted (PBKDF2-SHA256, 600k iterations). Unreadable without the passphrase, which is never stored here.
- `tools/notes_pack.py`: builds and encrypts `notes.enc.json`; run by a scheduled task.

API keys and the passphrase live only in the phone's browser storage.
