#!/usr/bin/env python3
"""Report what moved in apple/swift-nio-ssh since the last reviewed baseline.

Dependabot cannot do this for FeTerm: FeTerm pins this fork by revision, and
GitHub's advisory matching keys on apple/swift-nio-ssh, not on the fork URL.
So this job compares upstream against baseline.json, which records what a
FeTerm maintainer has already looked at:

  - the upstream main commit;
  - the newest release tag;
  - the published security advisories;
  - the open pull requests that touch Sources/, by head commit.

Anything new or changed is written to the job summary and the job fails, so
the repository owner gets GitHub's failure notification. Acknowledging it is a
deliberate commit that updates baseline.json, the same way the FeTerm pin
moves only by a deliberate edit.

Usage: watch.py BASELINE [--write-current PATH]
Needs GH_TOKEN (read-only access to public data is enough) and the gh CLI.
"""

import json
import os
import subprocess
import sys

UPSTREAM = "apple/swift-nio-ssh"


def gh(path):
    out = subprocess.run(
        ["gh", "api", "--paginate", "--slurp", path],
        check=True, capture_output=True, text=True,
    ).stdout
    pages = json.loads(out)
    if pages and isinstance(pages[0], list):
        return [item for page in pages for item in page]
    return pages[0] if len(pages) == 1 else pages


def current():
    main = gh(f"repos/{UPSTREAM}/commits/main")["sha"]
    releases = gh(f"repos/{UPSTREAM}/releases?per_page=100")
    release = releases[0]["tag_name"] if releases else None
    advisories = sorted(a["ghsa_id"] for a in gh(f"repos/{UPSTREAM}/security-advisories?per_page=100"))
    pulls = {}
    for pr in gh(f"repos/{UPSTREAM}/pulls?state=open&per_page=100"):
        files = gh(f"repos/{UPSTREAM}/pulls/{pr['number']}/files?per_page=100")
        if any(f["filename"].startswith("Sources/") for f in files):
            pulls[str(pr["number"])] = {"head": pr["head"]["sha"], "title": pr["title"]}
    return {"main": main, "release": release, "advisories": advisories, "pulls": pulls}


def diff(base, now):
    lines = []
    if now["main"] != base["main"]:
        lines.append(f"- upstream main moved: `{base['main'][:12]}` → `{now['main'][:12]}` "
                     f"([compare](https://github.com/{UPSTREAM}/compare/{base['main']}...{now['main']}))")
    if now["release"] != base["release"]:
        lines.append(f"- new release: `{base['release']}` → `{now['release']}`")
    for ghsa in sorted(set(now["advisories"]) - set(base["advisories"])):
        lines.append(f"- **new security advisory** [{ghsa}](https://github.com/{UPSTREAM}/security/advisories/{ghsa})")
    for number, pr in sorted(now["pulls"].items(), key=lambda kv: int(kv[0])):
        old = base["pulls"].get(number)
        link = f"[#{number}](https://github.com/{UPSTREAM}/pull/{number}) {pr['title']}"
        if old is None:
            lines.append(f"- new source PR {link}")
        elif old["head"] != pr["head"]:
            lines.append(f"- source PR updated {link}: `{old['head'][:12]}` → `{pr['head'][:12]}`")
    for number in sorted(set(base["pulls"]) - set(now["pulls"]), key=int):
        lines.append(f"- source PR #{number} closed or merged upstream: {base['pulls'][number]['title']}")
    return lines


def main(argv):
    base = json.load(open(argv[1]))
    now = current()
    if "--write-current" in argv:
        with open(argv[argv.index("--write-current") + 1], "w") as f:
            json.dump(now, f, indent=2, sort_keys=True)
            f.write("\n")
    lines = diff(base, now)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    text = ("## Upstream swift-nio-ssh moved\n\n" + "\n".join(lines)
            + "\n\nReview, then acknowledge by updating `.github/upstream-watch/baseline.json` "
              "with the current state the job log prints after this summary.\n") if lines else \
           "## Upstream swift-nio-ssh: nothing new since the baseline\n"
    print(text)
    if lines:
        print("Current state (paste into baseline.json once reviewed):")
        print(json.dumps(now, indent=2, sort_keys=True))
    if summary:
        with open(summary, "a") as f:
            f.write(text)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"main_moved={'true' if now['main'] != base['main'] else 'false'}\n")
    return 1 if lines else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
