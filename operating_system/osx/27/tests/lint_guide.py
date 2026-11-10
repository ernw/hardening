#!/usr/bin/env python3
"""Static checks for the guide: TOC, internal links, images, footnotes.

Usage: lint_guide.py <guide.md> [--fix-toc]
"""
import os
import re
import sys

TOC_START = re.compile(r"^- \[Hardening Guide", re.M)


def slug(text):
    text = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return text.replace(" ", "-")


def split(src):
    """Return (head, toc, body); the TOC is the list right after the title heading."""
    m = TOC_START.search(src)
    end = src.index("\n# ", m.start())
    return src[: m.start()], src[m.start(): end + 1], src[end + 1:]


def build_toc(src):
    head, _, body = split(src)
    title = re.search(r"^# (.+)$", head, re.M).group(1)
    seen = {slug(title): 0}
    lines = [f"- [{title}](#{slug(title)})"]
    in_code = False
    for line in body.split("\n[^1]: ")[0].splitlines():
        if line.startswith("```"):
            in_code = not in_code
        m = None if in_code else re.match(r"^(#{1,6}) (.+)$", line)
        if not m:
            continue
        text, anchor = m.group(2).strip(), slug(m.group(2))
        if anchor in seen:
            seen[anchor] += 1
            anchor = f"{anchor}-{seen[anchor]}"
        else:
            seen[anchor] = 0
        lines.append("  " * (len(m.group(1)) - 1) + f"- [{text}](#{anchor})")
    return "\n".join(lines) + "\n"


def lint(path, fix_toc=False):
    src = open(path).read()
    errors = []
    toc = build_toc(src)
    head, current, body = split(src)
    if current.strip() != toc.strip():
        if fix_toc:
            src = head + toc + body
            open(path, "w").write(src)
            print("TOC regenerated")
        else:
            errors.append("TOC is out of date (run with --fix-toc)")
    anchors = set(re.findall(r"\]\(#([^)]+)\)", toc))
    for link in sorted(set(re.findall(r"\]\(#([^)]+)\)", body))):
        if link not in anchors:
            errors.append(f"broken internal link: #{link}")
    base = os.path.dirname(path)
    images = re.findall(r'src="(img/[^"]+)"', body)
    errors += [f"missing image: {i}" for i in images if not os.path.exists(os.path.join(base, i))]
    img_dir = os.path.join(base, "img")
    if os.path.isdir(img_dir):
        errors += [f"unreferenced image: img/{f}" for f in sorted(os.listdir(img_dir)) if f"img/{f}" not in images]
    text, _, notes = body.partition("\n[^1]: ")
    used = set(re.findall(r"\[\^(\d+)\]", text))
    defined = set(re.findall(r"^\[\^(\d+)\]:", "[^1]: " + notes, re.M))
    errors += [f"undefined footnote [^{n}]" for n in sorted(used - defined, key=int)]
    errors += [f"unused footnote [^{n}]" for n in sorted(defined - used, key=int)]
    print(f"guide: {len(re.findall('VERIFY-27', body))} VERIFY-27 markers open, {len(errors)} errors")
    for e in errors:
        print("  ERROR:", e)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(lint(sys.argv[1], "--fix-toc" in sys.argv))
