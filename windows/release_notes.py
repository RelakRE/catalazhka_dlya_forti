"""Write the changelog section for one Windows GitHub release."""
import argparse
from pathlib import Path
import re


def release_notes(changelog: str, version: str) -> str:
    headings = {f"# Windows {version} Preview", f"# Forti Split {version} — Windows x64 Preview"}
    sections = re.split(r"(?m)^(?=# )", changelog)
    bodies = []
    for section in sections:
        title, _, body = section.partition("\n")
        if title.rstrip() in headings:
            bodies.append(body.strip())
    if len(bodies) != 1 or not bodies[0]:
        raise ValueError(f"Expected exactly one nonempty section for Windows {version}")
    return bodies[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source = Path(__file__).with_name("RELEASE-NOTES.md").read_text(encoding="utf-8-sig")
    args.output.write_text(release_notes(source, args.version) + "\n", encoding="utf-8")
