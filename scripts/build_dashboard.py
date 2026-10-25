"""Reassemble dashboard.html from dashboard_src/ (pure concatenation).

The dashboard's source of truth is the 11 fragments in ``dashboard_src/``;
the file the gateway serves is built from them, byte for byte:

    python scripts/build_dashboard.py            # write dashboard.html
    python scripts/build_dashboard.py --check    # verify only, exit 1 on drift

There is no transform, no minify, no template: concatenating the fragments in
their name order reproduces the shipped file exactly. That is what makes the
split safe - a fragment edit that survives ``--check`` is by definition a
change to what the panel serves, and tests/_test_dashboard_build.py runs the
check in CI so the two sides cannot drift.

Fragment naming carries the order (numeric prefix) and the role:

  10-head.html   doctype..<style>          50-body.html  </head><body>..markup
  20-style.css   the <style> element       60-66-*.js    panel script, by domain
  30-40-*.html   the two pre-body scripts  70-dashboard.js  the analytics page
                                           80-tail.html  </body></html>

The 60/62/64/66 fragments are INSIDE one <script> block (3981-9405 of the
built file): the cuts sit on top-level comment banners, and they are byte
ranges of that block, not standalone scripts - they cannot be linted or run
separately. `tests/_dashboard_sandbox.js` keeps exercising the built file.
"""
import os
import sys

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "dashboard_src")
OUT = os.path.join(os.path.dirname(SRC), "dashboard.html")


def built_bytes():
    names = sorted(n for n in os.listdir(SRC) if not n.startswith("."))
    blobs = []
    for name in names:
        with open(os.path.join(SRC, name), "rb") as f:
            blobs.append(f.read())
    return b"".join(blobs), names


def main():
    data, names = built_bytes()
    if "--check" in sys.argv[1:]:
        with open(OUT, "rb") as f:
            current = f.read()
        if current == data:
            print("dashboard.html matches dashboard_src/ (%d fragments, "
                  "%d bytes)" % (len(names), len(data)))
            return 0
        print("dashboard.html DOES NOT match dashboard_src/: run "
              "`python scripts/build_dashboard.py` after editing a fragment")
        return 1
    with open(OUT, "wb") as f:
        f.write(data)
    print("dashboard.html rebuilt from %d fragments (%d bytes)"
          % (len(names), len(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
