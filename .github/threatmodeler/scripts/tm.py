#!/usr/bin/env python3
"""Helper for the ThreatModeler PR pipeline.

Subcommands (all run from the repo root inside GitHub Actions):
  config        read .threatmodeler.yml and export values to GITHUB_OUTPUT
  prefilter     list changed files, decide if any are architecturally relevant
  baseline      work out how the model's sync point relates to where a PR branched
  mcp-config    write a Claude Code MCP config for the Nexus MCP server
  prompt        render a prompt template with run context
  validate      validate an agent result file against its JSON schema
  comment       render the PR comment and create/update it (sticky)
  policy        apply the policy to a PR result; set outputs, exit 1 if blocking
  last-result   extract the result JSON embedded in a PR's sticky comment
  pr-comment    post a plain markdown comment on a PR
  tool-args     print --allowedTools / --disallowedTools values for a job profile
  preflight     list the live Nexus MCP tools and check them against tools.yml
  merge-comment render the post-merge result as a PR comment
  leak-check    fail if a secret value appears in files about to be published

Only the standard library plus PyYAML and jsonschema are required.
"""
import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path.cwd()
TM_DIR = ROOT / ".tm"
HERE = Path(__file__).resolve().parent
MARKER = "<!-- tm-pr-check -->"
RESULT_RE = re.compile(r"<!-- tm-result-json:([A-Za-z0-9+/=]+) -->")
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
# Finding types mapped to the NexusAI 26.2 analysis categories, so what a
# developer sees in the PR uses the same words trainers use in Nexus.
CATEGORY_LABEL = {
    "countermeasure_gap": "Evidence verification",
    "control_removed": "Evidence verification",
    "new_attack_surface": "Architecture observation",
    "trust_boundary_change": "Architecture observation",
    "policy": "Policy",
}
STRENGTH_LABEL = {
    "declared_in_code": "declared in code",
    "stated_in_document": "stated in a document (review only)",
    "drawn_on_diagram": "drawn on the diagram (review only)",
    "stated_by_user": "stated by the user (review only)",
}


# --------------------------------------------------------------------------- utils

def load_config():
    with open(ROOT / ".threatmodeler.yml") as fh:
        return yaml.safe_load(fh)


def set_output(**pairs):
    path = os.environ.get("GITHUB_OUTPUT")
    lines = []
    for key, value in pairs.items():
        value = "" if value is None else str(value)
        if "\n" in value:
            lines.append(f"{key}<<__TM_EOF__\n{value}\n__TM_EOF__")
        else:
            lines.append(f"{key}={value}")
    if path:
        with open(path, "a") as fh:
            fh.write("\n".join(lines) + "\n")
    else:
        print("\n".join(lines))


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def glob_match(path, pattern):
    """fnmatch with '**' meaning any number of directories."""
    regex = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            regex += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            regex += ".*"
            i += 2
        else:
            ch = pattern[i]
            regex += "[^/]*" if ch == "*" else re.escape(ch) if ch != "?" else "[^/]"
            i += 1
    return re.fullmatch(regex, path) is not None


def gh_api(method, url, body=None):
    token = os.environ["GITHUB_TOKEN"]
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    req = urllib.request.Request(
        url if url.startswith("http") else f"{api}{url}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


def find_sticky_comment(repo, pr):
    page = 1
    while True:
        comments = gh_api("GET", f"/repos/{repo}/issues/{pr}/comments?per_page=100&page={page}")
        if not comments:
            return None
        for c in comments:
            if MARKER in (c.get("body") or ""):
                return c
        page += 1


# ------------------------------------------------------------------------ commands

def cmd_config(args):
    cfg = load_config()
    tm = cfg.get("threatmodeler", {})
    guid = (tm.get("project_guid") or "").strip()
    url = (tm.get("instance_url") or "").rstrip("/")
    if "YOUR-INSTANCE" in url or not url:
        sys.exit("::error::Set threatmodeler.instance_url in .threatmodeler.yml")
    if args.require_guid and not guid:
        sys.exit("::error::threatmodeler.project_guid is empty. Create the baseline threat model and set its GUID in .threatmodeler.yml.")
    set_output(
        instance_url=url,
        mcp_url=f"{url}/mcp",
        project_guid=guid,
        project_name=tm.get("project_name", ""),
        policy_mode=cfg.get("policy", {}).get("mode", "advisory"),
        review_label=cfg.get("policy", {}).get("review_label", "tm-architect-review"),
        label_format=cfg.get("versioning", {}).get("label_format", "pr-{pr}-{sha7}"),
        post_merge_mode=post_merge_mode(cfg),
        requirement_states=requirement_states(cfg),
        model_updates=model_updates(cfg),
    )


def post_merge_mode(cfg):
    raw = cfg.get("post_merge", {}).get("mode", "propose")
    # YAML reads a bare `off` as boolean false.
    mode = "off" if raw is False else str(raw).lower()
    if mode not in ("off", "propose", "apply"):
        sys.exit(f"::error::post_merge.mode must be off, propose or apply (got {mode})")
    return mode


def requirement_states(cfg):
    val = str(cfg.get("post_merge", {}).get("requirement_states", "suggest")).lower()
    if val not in ("suggest", "write"):
        sys.exit(f"::error::post_merge.requirement_states must be suggest or write (got {val})")
    return val


def model_updates(cfg):
    # pipeline: an apply run adds the merged changes to the diagram through
    # update_kis_diagram, then writes requirement statuses and the version.
    # nexus: the diagram is changed only in Nexus; an apply run checks it,
    # writes requirement statuses and saves the version.
    val = str(cfg.get("post_merge", {}).get("model_updates", "pipeline")).lower()
    if val not in ("nexus", "pipeline"):
        sys.exit(f"::error::post_merge.model_updates must be nexus or pipeline (got {val})")
    return val


def cmd_prefilter(args):
    cfg = load_config()
    patterns = cfg.get("architectural_paths", [])
    changed = [p for p in git("diff", "--name-only", f"{args.base}...{args.head}").splitlines() if p]
    relevant = [p for p in changed if any(glob_match(p, pat) for pat in patterns)]
    TM_DIR.mkdir(exist_ok=True)
    (TM_DIR / "changed-files.txt").write_text("\n".join(changed) + "\n")
    (TM_DIR / "relevant-files.txt").write_text("\n".join(relevant) + "\n")
    if relevant:
        diff = git("diff", "--unified=5", f"{args.base}...{args.head}", "--", *relevant)
        (TM_DIR / "diff.patch").write_text(diff)
    print(f"{len(changed)} changed file(s), {len(relevant)} architecturally relevant")
    set_output(relevant="true" if relevant else "false", relevant_count=len(relevant),
               changed_count=len(changed))


def _is_ancestor(a, b):
    return subprocess.run(["git", "merge-base", "--is-ancestor", a, b]).returncode == 0


def cmd_baseline(args):
    """Relate the model's sync point (tm-synced) to the commit this PR branched from.

    The PR's own change is always merge-base..head (what prefilter diffs). The
    model reflects tm-synced, which can be behind the merge base (merges not yet
    applied) or ahead of it (merges applied after the PR branched). Either way
    the gap must not be attributed to this PR, so it goes in its own patch.
    """
    cfg = load_config()
    patterns = cfg.get("architectural_paths", [])
    TM_DIR.mkdir(exist_ok=True)
    merge_base = git("merge-base", args.base, args.head).strip()
    try:
        synced = git("rev-list", "-n1", "tm-synced").strip()
    except subprocess.CalledProcessError:
        synced = ""

    gap_range = None
    if post_merge_mode(cfg) == "off" or not synced:
        state = "untracked"
    elif synced == merge_base:
        state = "in_sync"
    elif _is_ancestor(synced, merge_base):
        state, gap_range = "model_behind", (synced, merge_base)
    elif _is_ancestor(merge_base, synced):
        state, gap_range = "branch_behind", (merge_base, synced)
    else:
        state = "diverged"

    gap = []
    if gap_range:
        changed = git("diff", "--name-only", f"{gap_range[0]}..{gap_range[1]}").splitlines()
        gap = [p for p in changed if p and any(glob_match(p, pat) for pat in patterns)]
        if gap:
            (TM_DIR / "baseline-gap.patch").write_text(
                git("diff", "--unified=5", f"{gap_range[0]}..{gap_range[1]}", "--", *gap))
        else:
            state = "in_sync"  # only non-architectural commits in between

    mb7, s7 = merge_base[:7], synced[:7]
    files = ", ".join(f"`{p}`" for p in gap)
    context = {
        "in_sync": f"CI last synced the model at the commit this PR branched from (`{mb7}`), "
                   "or only non-architectural commits lie between them. Treat the model as "
                   "matching the code at that commit.",
        "model_behind": f"CI last synced the model at `{s7}`. Architecture changes merged to main "
                        f"after that and before this PR branched from `{mb7}` are in "
                        f"`.tm/baseline-gap.patch` ({files}). They are already on main but may "
                        "be missing from the model, unless a post-merge apply run or a person "
                        "added them. They are not part of this PR.",
        "branch_behind": f"CI last synced the model at `{s7}`, which includes changes merged to "
                         f"main after this PR branched from `{mb7}`. Those changes are in "
                         f"`.tm/baseline-gap.patch` ({files}). This PR's branch does not contain "
                         "them, so their absence from its files is not a removal.",
        "untracked": "CI does not track which commit the model reflects (it is kept current by "
                     "hand in Nexus), so it may lag or lead main.",
        "diverged": f"The tag tm-synced (`{s7}`) is not on this PR's history, so CI cannot tell "
                    "which commit the model reflects.",
    }[state]
    (TM_DIR / "baseline-context.md").write_text(context + "\n")
    print(f"Baseline state: {state} (merge base {mb7}, tm-synced {s7 or 'missing'})")
    set_output(baseline_state=state, merge_base=merge_base, synced_sha=synced or merge_base)


def cmd_mcp_config(args):
    if not os.environ.get("TM_API_KEY"):
        sys.exit("::error::TM_API_KEY secret is not set")
    # The key itself never goes in the file: Claude Code expands ${TM_API_KEY}
    # from its own environment when it connects, so nothing the agent can read
    # on disk holds the key.
    config = {
        "mcpServers": {
            "threatmodeler": {
                "type": "http",
                "url": args.url,
                "headers": {"X-ThreatModeler-ApiKey": "${TM_API_KEY}"},
            }
        }
    }
    out = Path(args.out)
    out.write_text(json.dumps(config, indent=2))
    out.chmod(0o600)
    print(f"MCP config written to {out}")


def cmd_prompt(args):
    template = Path(args.template).read_text()
    ctx = dict(kv.split("=", 1) for kv in args.var)
    for name in args.file_var or []:
        key, path = name.split("=", 1)
        p = Path(path)
        ctx[key] = p.read_text().strip() if p.exists() else "(none)"

    def sub(m):
        key = m.group(1)
        if key not in ctx:
            sys.exit(f"::error::prompt variable {key} not provided")
        return ctx[key]

    Path(args.out).write_text(re.sub(r"\{\{\s*([A-Z0-9_]+)\s*\}\}", sub, template))


def cmd_validate(args):
    import jsonschema

    schema = json.loads((HERE.parent / "schema" / f"{args.kind}-result.schema.json").read_text())
    path = Path(args.file)
    if not path.exists():
        sys.exit(f"::error::Agent did not write {path}. See the agent transcript artifact.")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        sys.exit(f"::error::{path} is not valid JSON: {exc}")
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(data), key=lambda e: e.path)
    for e in errors:
        loc = "/".join(str(p) for p in e.path) or "(root)"
        print(f"::error::{path.name} {loc}: {e.message}")
    if errors:
        sys.exit(1)
    print(f"{path} is valid")


def _sev_rank(sev):
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _blocking(result, cfg):
    block_on = set(cfg.get("policy", {}).get("block_on_severity", ["critical", "high"]))
    return [f for f in result.get("findings", []) if f.get("blocking") or f.get("severity") in block_on]


def render_pr_comment(result, cfg, ctx):
    sig = result["significance"]
    blocking = _blocking(result, cfg)
    mode = cfg.get("policy", {}).get("mode", "advisory")
    badge = {"significant": "🔶 Significant", "minor": "🔹 Minor", "none": "⚪ None"}[sig]
    status = "❌ Blocking findings" if blocking and mode == "enforce" else (
        "⚠️ Findings (advisory)" if result["findings"] else "✅ No findings")

    out = [MARKER, "## ThreatModeler architecture check", ""]
    out.append(f"**Architectural impact:** {badge} · **Result:** {status}  ")
    synced = ("" if post_merge_mode(cfg) == "off"
              else f" (CI last applied changes at `{ctx['synced_sha'][:7]}`)")
    out.append(f"Compared `{ctx['head_sha'][:7]}` against the current baseline model "
               f"[{result['model'].get('name') or 'project'}]({ctx['instance_url']}){synced}.")
    out += ["", result["summary"], ""]
    lag = {
        "model_behind": "the model may not yet include architecture changes already merged to main",
        "branch_behind": "the model includes changes merged to main after this branch was created",
        "diverged": "CI could not tell which commit the model reflects",
    }.get(ctx["baseline_state"])
    if lag or result.get("baseline_note"):
        note = result.get("baseline_note") or ""
        out.append(f"> ⚠️ **Baseline note:** {lag + '. ' if lag else ''}{note}".rstrip())
        out.append("> Those differences are not attributed to this PR.")
        out.append("")
    if sig == "significant":
        out.append(f"> **Architect review requested** — {result['significance_reason']}")
        out.append("")

    findings = sorted(result["findings"], key=lambda f: _sev_rank(f["severity"]))
    if findings:
        out.append(f"### Findings ({len(findings)})")
        for f in findings:
            ev = f.get("evidence", {})
            loc = f"`{ev.get('file')}:{ev.get('line')}`" if ev.get("file") else ""
            block = " · **blocking**" if f in blocking else ""
            cat = CATEGORY_LABEL.get(f["type"], f["type"])
            out.append(f"#### {f['severity'].upper()} — {f['title']}{block}")
            out.append(f"<sub>{cat}</sub>  ")
            out.append(f"{f['explanation']}  ")
            meta = [f"Component: **{f['component']}**"]
            if f.get("requirement", {}).get("name"):
                meta.append(f"Requirement: {f['requirement']['name']}")
            if loc:
                meta.append(f"Where: {loc}")
            if f.get("evidence_strength"):
                meta.append(f"Evidence: {STRENGTH_LABEL.get(f['evidence_strength'], f['evidence_strength'])}")
            out.append(" · ".join(meta))
            fix = f.get("fix") or {}
            if fix.get("summary"):
                out.append(f"\n**Fix:** {fix['summary']}")
            if fix.get("suggested_code"):
                lang = fix.get("language", "")
                out.append(f"```{lang}\n{fix['suggested_code'].rstrip()}\n```")
            out.append("")

    changes = result.get("architecture_changes", [])
    if changes:
        out.append("<details><summary>Model delta ({} change{})</summary>\n".format(
            len(changes), "" if len(changes) == 1 else "s"))
        out.append("| Change | Type | Element | Source |")
        out.append("|---|---|---|---|")
        for c in changes:
            src = c.get("source", {})
            out.append(f"| {c['change']} | {c['element_type']} | {c['name']} | "
                       f"{src.get('file', '')}{':' + str(src['line']) if src.get('line') else ''} |")
        out.append("\n</details>\n")

    sat = result.get("requirements_satisfied", [])
    if sat:
        if post_merge_mode(cfg) == "apply" and requirement_states(cfg) == "write":
            how = "state is written in Nexus when the post-merge apply run is approved"
        else:
            how = "suggested only — a reviewer sets the status in Nexus"
        out.append("<details><summary>Requirements this change appears to implement "
                   f"({len(sat)}) — {how}</summary>\n")
        for r in sat:
            ev = r.get("evidence", {})
            strength = STRENGTH_LABEL.get(r.get("evidence_strength", ""), "")
            out.append(f"- **{r['name']}** on {r['component']} — `{ev.get('file')}:{ev.get('line')}`"
                       + (f" ({strength})" if strength else ""))
        out.append("\n</details>\n")

    pm = post_merge_mode(cfg)
    if pm == "apply" and model_updates(cfg) == "nexus":
        maint = "after merge an architect approves the model update in Nexus and CI saves the version"
    else:
        maint = {
            "off": "after merge the model is updated in Nexus",
            "propose": "after merge CI proposes model changes for review",
            "apply": "after merge CI applies model changes once a person approves the run",
        }[pm]
    out.append(f"<sub>Run [{ctx['run_id']}]({ctx['run_url']}) · policy mode `{mode}` · "
               f"this check never changes Nexus; {maint}.</sub>")
    payload = base64.b64encode(json.dumps(
        {**result, "_head_sha": ctx["head_sha"]}, separators=(",", ":")).encode()).decode()
    out.append(f"<!-- tm-result-json:{payload} -->")
    return "\n".join(out)


def upsert_comment(repo, pr, body):
    existing = find_sticky_comment(repo, pr)
    if existing:
        gh_api("PATCH", f"/repos/{repo}/issues/comments/{existing['id']}", {"body": body})
        print(f"Updated comment {existing['id']}")
    else:
        c = gh_api("POST", f"/repos/{repo}/issues/{pr}/comments", {"body": body})
        print(f"Created comment {c['id']}")


def cmd_comment(args):
    cfg = load_config()
    repo, pr = os.environ.get("GITHUB_REPOSITORY", "local/repo"), args.pr
    ctx = {
        "head_sha": args.head_sha,
        "synced_sha": args.synced_sha or "unknown",
        "baseline_state": args.baseline_state or "in_sync",
        "instance_url": cfg["threatmodeler"]["instance_url"],
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "run_url": f"{os.environ.get('GITHUB_SERVER_URL', '')}/{repo}/actions/runs/"
                   f"{os.environ.get('GITHUB_RUN_ID', '')}",
    }
    if args.skip_reason:
        body = "\n".join([MARKER, "## ThreatModeler architecture check", "",
                          f"⚪ **No architectural change** — {args.skip_reason}", "",
                          f"<sub>Commit `{args.head_sha[:7]}` · the agent did not run.</sub>"])
    elif args.error:
        body = "\n".join([MARKER, "## ThreatModeler architecture check", "",
                          f"⚠️ **The check could not complete:** {args.error}", "",
                          f"<sub>See [run {ctx['run_id']}]({ctx['run_url']}) for the transcript.</sub>"])
    else:
        result = json.loads(Path(args.file).read_text())
        body = render_pr_comment(result, cfg, ctx)
    Path(TM_DIR).mkdir(exist_ok=True)
    (TM_DIR / "comment.md").write_text(body)
    if args.dry_run:
        print(body)
        return
    upsert_comment(repo, pr, body)


def cmd_policy(args):
    cfg = load_config()
    result = json.loads(Path(args.file).read_text())
    mode = cfg.get("policy", {}).get("mode", "advisory")
    blocking = _blocking(result, cfg)
    set_output(significance=result["significance"], findings=len(result["findings"]),
               blocking=len(blocking))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and (TM_DIR / "comment.md").exists():
        with open(summary, "a") as fh:
            fh.write((TM_DIR / "comment.md").read_text() + "\n")
    if blocking and mode == "enforce":
        for f in blocking:
            ev = f.get("evidence", {})
            loc = f"file={ev['file']},line={ev.get('line', 1)}," if ev.get("file") else ""
            print(f"::error {loc}title=ThreatModeler: {f['severity']}::{f['title']}")
        sys.exit(1)


def cmd_last_result(args):
    repo = os.environ["GITHUB_REPOSITORY"]
    c = find_sticky_comment(repo, args.pr)
    m = RESULT_RE.search(c["body"]) if c else None
    TM_DIR.mkdir(exist_ok=True)
    out = Path(args.out)
    if not m:
        out.write_text("{}")
        print(f"No PR check result found on #{args.pr}")
        return
    out.write_text(json.dumps(json.loads(base64.b64decode(m.group(1))), indent=2))
    print(f"Wrote PR #{args.pr} check result to {out}")


def cmd_pr_comment(args):
    repo = os.environ["GITHUB_REPOSITORY"]
    gh_api("POST", f"/repos/{repo}/issues/{args.pr}/comments", {"body": Path(args.file).read_text()})


def _mcp(name):
    return f"mcp__threatmodeler__{name}"


def load_tools():
    return yaml.safe_load((HERE.parent / "tools.yml").read_text())


def profile_tools(tools, profile):
    prof = tools["profiles"][profile]
    names = []
    for group in prof.get("allow", []):
        names += tools[group]
    names += prof.get("extra", [])
    return list(dict.fromkeys(names))


def cmd_tool_args(args):
    tools = load_tools()
    allowed = profile_tools(tools, args.profile)
    if args.requirement_write:
        allowed += [t for t in profile_tools(tools, "requirement-write") if t not in allowed]
    # Deny every ThreatModeler tool the profile doesn't allow, not just the
    # write tools: the live list comes from the preflight step. Without it,
    # fall back to denying the known write tools.
    live_file = TM_DIR / "mcp-tools.json"
    live = json.loads(live_file.read_text()).get("live", []) if live_file.exists() else []
    denied = sorted({t for t in list(tools["write_all"]) + live if t not in allowed})
    # No `git diff`: with --no-index it prints any file on the runner. The
    # diffs the agent needs are precomputed in .tm/. Reads of the runner's temp
    # folder and /proc (process environments) are denied outright; Claude Code
    # applies Read rules to Grep and Glob as well. The leak check is the backstop.
    local = ["Read", "Glob", "Grep", "Write", "Bash(git show:*)", "Bash(git log:*)"]
    runner_temp = os.environ.get("RUNNER_TEMP", "/home/runner/work/_temp").rstrip("/")
    blocked = [f"Read(/{path}/**)" for path in (runner_temp, "/proc")]
    set_output(allowed=",".join([_mcp(t) for t in allowed] + local),
               denied=",".join([_mcp(t) for t in denied] + blocked))


# Secrets that must never appear in anything the pipeline publishes.
SECRET_ENV = ("TM_API_KEY", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN")


def cmd_leak_check(args):
    """Fail if a secret value appears in any file under the given paths.

    Runs before anything in .tm/ is uploaded or posted, because GitHub masks
    secrets in logs but not in artifacts or PR comments. Never prints a value.
    """
    secrets = {}
    for name in SECRET_ENV:
        val = os.environ.get(name, "")
        if len(val) >= 8:
            secrets[name] = [val.encode(), base64.b64encode(val.encode())]
    if not secrets:
        sys.exit("::error::leak-check found no secrets in its environment to check for")
    hits = []
    for root in args.path:
        root = Path(root)
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
        for f in files:
            data = f.read_bytes()
            for name, forms in secrets.items():
                if any(form in data for form in forms):
                    hits.append((f, name))
    for f, name in hits:
        print(f"::error::{name} found in {f}; nothing from this run will be uploaded or posted")
    if hits:
        # Don't leave the leaked copies for a later step to pick up.
        for f in {f for f, _ in hits}:
            f.unlink()
        sys.exit(1)
    print(f"Leak check passed: {', '.join(secrets)} not found under {', '.join(args.path)}")


def _rpc(url, key, method, params, rid, session=None):
    body = {"jsonrpc": "2.0", "method": method, "params": params}
    if rid is not None:
        body["id"] = rid
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "X-ThreatModeler-ApiKey": key}
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, method="POST", data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        sid = resp.headers.get("Mcp-Session-Id") or session
        raw = resp.read().decode()
        ctype = resp.headers.get("Content-Type", "")
    if rid is None or not raw.strip():
        return None, sid
    if "text/event-stream" in ctype:
        data = [ln[5:].strip() for ln in raw.splitlines() if ln.startswith("data:")]
        msgs = [json.loads(d) for d in data if d]
        msg = next((m for m in msgs if m.get("id") == rid), msgs[-1] if msgs else {})
    else:
        msg = json.loads(raw)
    if "error" in msg:
        sys.exit(f"::error::MCP {method} failed: {msg['error']}")
    return msg.get("result", {}), sid


def _preflight_fail(msg):
    """Stop the job, leaving the reason where the PR comment step can show it."""
    TM_DIR.mkdir(exist_ok=True)
    (TM_DIR / "preflight-error.txt").write_text(msg)
    sys.exit(f"::error::{msg}")


def cmd_preflight(args):
    key = os.environ.get("TM_API_KEY")
    if not key:
        _preflight_fail("the TM_API_KEY secret is not set")
    try:
        init, sid = _rpc(args.url, key, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "tm-cicd-preflight", "version": "1"}}, 1)
        _rpc(args.url, key, "notifications/initialized", {}, None, sid)
        live, cursor, rid = [], None, 2
        while True:
            res, sid = _rpc(args.url, key, "tools/list", {"cursor": cursor} if cursor else {}, rid, sid)
            live += [t["name"] for t in res.get("tools", [])]
            cursor = res.get("nextCursor")
            rid += 1
            if not cursor:
                break
    except urllib.error.HTTPError as exc:
        hint = " (the key's user may be missing the MCP Access role)" if exc.code == 403 else ""
        _preflight_fail(f"the ThreatModeler MCP server returned HTTP {exc.code}{hint}")
    except urllib.error.URLError as exc:
        _preflight_fail(f"cannot reach the ThreatModeler MCP server at {args.url}: {exc.reason}")

    tools = load_tools()
    needed = set()
    for prof in tools["profiles"]:
        needed |= set(profile_tools(tools, prof))
    known = needed | set(tools["read"]) | set(tools["write_all"])
    missing = sorted(needed - set(live))
    gone_denied = sorted((set(tools["write_all"]) - needed) - set(live))
    new = sorted(set(live) - known)
    for t in gone_denied:
        print(f"::notice::Deny-listed tool not on the live server (harmless): {t}")
    TM_DIR.mkdir(exist_ok=True)
    server = (init or {}).get("serverInfo", {})
    (TM_DIR / "mcp-tools.json").write_text(json.dumps(
        {"server": server, "live": sorted(live), "missing": missing,
         "deny_listed_but_absent": gone_denied, "not_in_tools_yml": new}, indent=2))
    print(f"Nexus MCP server {server.get('name', '?')} {server.get('version', '')}: {len(live)} tools")
    for t in new:
        print(f"::notice::Live tool not in tools.yml (unused by the pipeline): {t}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(f"**Nexus MCP preflight:** {len(live)} tools live, "
                     f"{len(missing)} expected but missing, {len(new)} new.\n\n")
            if missing:
                fh.write("Missing: " + ", ".join(f"`{m}`" for m in missing) + "\n\n")
            if new:
                fh.write("New (not used yet): " + ", ".join(f"`{m}`" for m in new) + "\n\n")
    if missing:
        for t in missing:
            print(f"::error::Tool in tools.yml is not on the live server: {t}")
        _preflight_fail("the ThreatModeler tool check failed: tools.yml lists "
                        + ", ".join(f"`{t}`" for t in missing)
                        + ", which the ThreatModeler MCP server doesn't have. "
                          "A ThreatModeler upgrade may have renamed or removed it; update tools.yml.")


def _mcp_tool(url, key, tool, arguments):
    """Call one MCP tool and return its result as a dict (JSON text content)."""
    _, sid = _rpc(url, key, "initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "tm-cicd-check", "version": "1"}}, 1)
    _rpc(url, key, "notifications/initialized", {}, None, sid)
    res, _ = _rpc(url, key, "tools/call", {"name": tool, "arguments": arguments}, 2, sid)
    if res.get("structuredContent"):
        return res["structuredContent"]
    text = "".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = {"success": False, "error": text[:500]}
    if res.get("isError"):
        data.setdefault("success", False)
    return data


def cmd_diagram_counts(args):
    """Count the model's elements and flows, read from ThreatModeler, not the agent."""
    data = _mcp_tool(args.url, os.environ["TM_API_KEY"], "list_project_components",
                     {"projectGuid": args.project, "includeLinks": True})
    if data.get("success") is False:
        sys.exit(f"::error::list_project_components failed: {data.get('error', data)}")
    entries = data.get("components", [])
    keys = [e.get("key") for e in entries]
    counts = {
        "elements": sum(1 for e in entries if e.get("category") != "Link"),
        "flows": len(data.get("links", [])),
        "duplicate_keys": sorted({k for k in keys if keys.count(k) > 1}, key=str),
    }
    Path(args.out).write_text(json.dumps(counts, indent=2))
    print(f"Model {args.project}: {counts['elements']} elements, {counts['flows']} flows"
          + (f", duplicate keys {counts['duplicate_keys']}" if counts["duplicate_keys"] else ""))


def cmd_save_version(args):
    """Save the version only if the diagram changed exactly as the agent reported."""
    r = json.loads(Path(args.file).read_text())
    before = json.loads(Path(args.before).read_text())
    after = json.loads(Path(args.after).read_text())
    actions = [c.get("action", "").lower() for c in r.get("model_changes", [])]
    flows_added = sum(1 for a in actions if "flow" in a)
    elements_added = sum(1 for a in actions if "add" in a and "flow" not in a)
    problems = []
    if after["elements"] - before["elements"] != elements_added:
        problems.append(f"the model has {after['elements'] - before['elements']} new elements, "
                        f"but the run reported {elements_added}")
    if after["flows"] - before["flows"] != flows_added:
        problems.append(f"the model has {after['flows'] - before['flows']} new flows, "
                        f"but the run reported {flows_added}")
    if after["duplicate_keys"]:
        problems.append(f"diagram keys {after['duplicate_keys']} are used twice")
    r["diagram_check"] = {"before": before, "after": after,
                          "reported": {"elements_added": elements_added, "flows_added": flows_added},
                          "ok": not problems}
    r["version_created"] = False
    if problems:
        r.setdefault("errors", []).append("No version was saved: " + "; ".join(problems) + ".")
    elif r.get("version_due"):
        notes = (r.get("version_notes") or "").strip()
        res = _mcp_tool(args.url, os.environ["TM_API_KEY"], "create_project_version",
                        {"projectGuid": r["project_guid"], "version": args.label,
                         "notes": notes[:2000], "includeImage": True})
        if res.get("success") is False:
            problems.append(f"create_project_version failed for label {args.label}: "
                            f"{res.get('error', res)}")
            r.setdefault("errors", []).append(problems[-1])
        else:
            r["version_created"] = True
            r["version_label"] = args.label
    Path(args.file).write_text(json.dumps(r, indent=2))
    print(json.dumps(r["diagram_check"], indent=2))
    if problems:
        for p in problems:
            print(f"::error::{p}")
        sys.exit(1)
    print(f"Version {args.label} saved." if r["version_created"] else "No version due.")


def cmd_merge_comment(args):
    r = json.loads(Path(args.file).read_text())
    applied = r.get("mode") == "apply"
    lines = ["<!-- tm-post-merge -->"]
    if applied:
        lines.append("## ThreatModeler model updated")
        lines.append("")
        if r["version_created"]:
            lines.append(f"Saved version **{r['version_label']}** of the baseline model.")
        elif r.get("missing_from_model"):
            lines.append("⏳ The model in Nexus doesn't reflect this merge yet, so nothing was written and no "
                         "version was saved. Add the changes listed below in the Nexus diagram editor, "
                         "then run **TM post-merge sync** with *apply* checked again.")
        else:
            lines.append("⚠️ The model update did not complete; no version was saved.")
    else:
        lines.append("## ThreatModeler: proposed model update")
        lines.append("")
        lines.append("Nothing was changed in Nexus. A person applies this by running **TM post-merge sync** "
                     "with *apply* checked.")
    if r.get("version_notes"):
        lines += ["", r["version_notes"]]
    if r["model_changes"]:
        lines += ["", "**Model changes**" + ("" if applied else " (proposed)")]
        lines += [f"- {c['action']}: {c['element']}" for c in r["model_changes"]]
    if applied and r.get("missing_from_model"):
        lines += ["", "**Not yet in the model** (add these in the Nexus diagram editor)"]
        lines += [f"- {m['element']}" + (f" (`{m['file']}`)" if m.get("file") else "")
                  for m in r["missing_from_model"]]
    if r["requirement_updates"]:
        lines += ["", "**Requirement statuses written**"]
        lines += [f"- {u['name']}: {u.get('old_status', '?')} → {u['new_status']}" for u in r["requirement_updates"]]
    props = r.get("requirement_suggestions", [])
    if props:
        lines += ["", "**Requirement statuses to review in Nexus** (suggested, not applied)"]
        for p in props:
            ev = p.get("evidence", {})
            lines.append(f"- {p['name']} on {p['component']}: `{ev.get('file')}:{ev.get('line')}` "
                         f"({STRENGTH_LABEL.get(p.get('evidence_strength', ''), 'evidence')})")
    if r["errors"]:
        lines += ["", "**Errors**"] + [f"- {e}" for e in r["errors"]]
    body = "\n".join(lines) + "\n"
    Path(args.out).write_text(body)
    print(body)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("config"); s.add_argument("--require-guid", action="store_true")
    s.set_defaults(fn=cmd_config)

    s = sub.add_parser("prefilter"); s.add_argument("--base", required=True)
    s.add_argument("--head", required=True); s.set_defaults(fn=cmd_prefilter)

    s = sub.add_parser("baseline"); s.add_argument("--base", required=True)
    s.add_argument("--head", required=True); s.set_defaults(fn=cmd_baseline)

    s = sub.add_parser("mcp-config"); s.add_argument("--url", required=True)
    s.add_argument("--out", required=True); s.set_defaults(fn=cmd_mcp_config)

    s = sub.add_parser("prompt"); s.add_argument("--template", required=True)
    s.add_argument("--out", required=True); s.add_argument("--var", action="append", default=[])
    s.add_argument("--file-var", action="append"); s.set_defaults(fn=cmd_prompt)

    s = sub.add_parser("validate"); s.add_argument("--kind", required=True, choices=["pr", "merge", "bootstrap"])
    s.add_argument("--file", required=True); s.set_defaults(fn=cmd_validate)

    s = sub.add_parser("comment"); s.add_argument("--pr", required=True)
    s.add_argument("--head-sha", required=True); s.add_argument("--synced-sha")
    s.add_argument("--baseline-state")
    s.add_argument("--file"); s.add_argument("--skip-reason"); s.add_argument("--error")
    s.add_argument("--dry-run", action="store_true"); s.set_defaults(fn=cmd_comment)

    s = sub.add_parser("policy"); s.add_argument("--file", required=True); s.set_defaults(fn=cmd_policy)

    s = sub.add_parser("last-result"); s.add_argument("--pr", required=True)
    s.add_argument("--out", required=True); s.set_defaults(fn=cmd_last_result)

    s = sub.add_parser("pr-comment"); s.add_argument("--pr", required=True)
    s.add_argument("--file", required=True); s.set_defaults(fn=cmd_pr_comment)

    s = sub.add_parser("tool-args"); s.add_argument("--profile", required=True)
    s.add_argument("--requirement-write", action="store_true"); s.set_defaults(fn=cmd_tool_args)

    s = sub.add_parser("preflight"); s.add_argument("--url", required=True); s.set_defaults(fn=cmd_preflight)

    s = sub.add_parser("leak-check"); s.add_argument("--path", action="append", required=True)
    s.set_defaults(fn=cmd_leak_check)

    s = sub.add_parser("merge-comment"); s.add_argument("--file", required=True)
    s.add_argument("--out", required=True); s.set_defaults(fn=cmd_merge_comment)

    s = sub.add_parser("diagram-counts"); s.add_argument("--url", required=True)
    s.add_argument("--project", required=True); s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_diagram_counts)

    s = sub.add_parser("save-version"); s.add_argument("--url", required=True)
    s.add_argument("--file", required=True); s.add_argument("--before", required=True)
    s.add_argument("--after", required=True); s.add_argument("--label", required=True)
    s.set_defaults(fn=cmd_save_version)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
