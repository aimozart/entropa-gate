Entropa Gate (client app), Linux x86_64
=======================================
What this is: the client-installed app that records signed, data-minimal decisions in a ledger YOU hold, with a key YOU create.
Nothing here phones home, auto-updates or sends telemetry. The program has no network code.

Install (as an ordinary user, no root):
  1. Get the release public key from a SECOND channel (the release page you reached separately).
  2. tar -xzf entropa-gate-VERSION-linux-x86_64.tar.gz && cd entropa-gate-VERSION
  3. sh ./install.sh --minisign-pubkey RW...            (preferred; needs minisign)
     or  sh ./install.sh --pubkey <ML-DSA public key hex>   (weaker: see below)
  The installer verifies every file BEFORE copying, installs to ~/.local/bin, tells you which verification mode it used and what it did not check,
  and never edits your shell files. If ~/.local/bin is not on your PATH it prints the one line to add.
  Hostile download? Check it yourself first: minisign -V -P RW... -m SHA256SUMS && sha256sum -c SHA256SUMS

Use:  entropa-gate init --dir ~/entropa-node     creates your signing key (platinum.key, mode 0600) and the ledger
      entropa-gate record --dir DIR < request.json   |   entropa-gate verify --dir DIR   |   entropa-gate status --dir DIR
Remove: sh ~/.local/share/entropa-gate/uninstall.sh   (the INSTALLED copy, in the share directory of your prefix, not the one in the tarball folder;
        it removes only what was installed; your keys and ledgers stay)

Limits: the ML-DSA mode uses a verifier from this same tarball, so it cannot protect against a hostile download; a verified signature shows
who signed which bytes, not that the code is safe or independently reviewed; reproducibility was measured on one machine; Linux x86_64 only
(glibc, statically linked; tested on one distribution).
