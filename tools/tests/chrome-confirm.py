#!/usr/bin/env python3
"""The chrome's question window takes focus when it maps, so it counts only
the code it shows, typed after it shows: a "y" and Enter meant for another
window, a hostile zone's among them, or a half-typed line, must not answer it."""
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import time

PROMPT = rb"Type (\d+) and Enter"


def read_until(fd, marker, seconds=15):
    """What the window has shown, up to and including MARKER (a regex)."""
    seen = b""
    deadline = time.monotonic() + seconds
    while not re.search(marker, seen):
        left = deadline - time.monotonic()
        chunk = b""
        if left > 0 and select.select([fd], [], [], left)[0]:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                pass
        if not chunk:
            raise AssertionError(f"the window never showed {marker!r}: {seen.decode(errors='replace')!r}")
        seen += chunk
    return seen


def main():
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="kryptik-chrome-confirm-") as tmp:
        work = Path(tmp)
        consent = work / "consent"
        consent.mkdir()
        # The real chrome, its question directory pointed at the test's.
        source = (root / "tools/desktop/kryptik-chrome").read_text()
        definition = "CONSENT=/run/kryptik-consent"
        assert source.count(definition) == 1, "update the test's substitution for CONSENT"
        chrome = work / "chrome"
        chrome.write_text(source.replace(definition, f"CONSENT={consent}"))
        chrome.chmod(0o700)

        def confirm(kind, early, late, plant=None):
            """One question, with EARLY typed before it shows and LATE after it
            asks ({code} is the code shown), and a link to PLANT at the answer's
            temporary name if given. Returns (answer or None, what it showed)."""
            ident = f"q-{kind}"
            if kind == "clock":
                ask = "kind=clock\nnow=2026-09-27 10:00:00\nproposed=2026-09-28 10:00:00\nsources=4\n"
            else:
                ask = "from=untrusted\nto=work\nname=f.txt\nbytes=3\n"
            (consent / f"{ident}.ask").write_text(ask)
            for suffix in ("answer", "code", "answer.tmp"):
                (consent / f"{ident}.{suffix}").unlink(missing_ok=True)
            if plant:
                os.symlink(plant, consent / f"{ident}.answer.tmp")
            master, slave = os.openpty()
            os.write(master, early)
            proc = subprocess.Popen(
                [str(chrome), "--confirm", ident], stdin=slave, stdout=slave, stderr=slave,
                start_new_session=True, env={**os.environ, "XDG_RUNTIME_DIR": str(work)},
            )
            os.close(slave)
            try:
                shown = read_until(master, PROMPT)
                code = re.search(PROMPT, shown).group(1).decode()
                kept = (consent / f"{ident}.code").read_text().strip()
                assert kept == code, f"the code beside the question ({kept}) is not the one shown ({code})"
                os.write(master, late.replace("{code}", code).encode())
                proc.wait(timeout=10)
            finally:
                if proc.poll() is None:
                    proc.kill()
                os.close(master)
            answer = consent / f"{ident}.answer"
            return (answer.read_text().strip() if answer.exists() else None), shown.decode(errors="replace")

        cases = [
            # what, question, typed before it shows, typed after it asks, answer, says it dropped keys
            ("the code, typed after it asks", "transfer", b"", "{code}\n", "yes", False),
            ("y and Enter typed before it showed, then the code", "transfer", b"y\n", "{code}\n", "yes", True),
            ("a half-typed line before it showed, then the code", "transfer", b"4", "{code}\n", "yes", True),
            ("a plain y", "transfer", b"", "y\n", "no", False),
            ("the clock question, answered the same way", "clock", b"", "{code}\n", "yes", False),
        ]
        for what, kind, early, late, want, dropped in cases:
            got, shown = confirm(kind, early, late)
            assert got == want, f"{what}: answered {got!r}, wanted {want!r}\n{shown}"
            assert ("is ignored" in shown) == dropped, f"{what}: the note on early keys {'missing' if dropped else 'shown'}\n{shown}"
            print(f"PASS: {what}: {got}")

        # Any member of group kryptik can plant a link in the directory: the
        # window's writes must not follow one, and the answer is then a refusal.
        victim = work / "victim"
        victim.write_text("untouched\n")
        got, shown = confirm("transfer", b"", "{code}\n", plant=victim)
        assert victim.read_text() == "untouched\n", "the window wrote through a link planted at its answer's temporary name"
        assert got is None, f"an answer was recorded through a planted link: {got!r}"
        print("PASS: a link planted at the answer's temporary name is not followed, and nothing is recorded")


if __name__ == "__main__":
    main()
