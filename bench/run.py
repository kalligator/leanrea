"""Run one benchmark cell: python3 -I run.py <arm> <task_id> <rep>.
Arms: rea | leanrea | none.
Supports Claude Code, Gemini/Antigravity CLI, or any generic agent CLI via BENCH_AGENT.
Needs ./setup.sh first. Work dir: $LEANREA_WORK (default ./work)."""
import json, os, re, shutil, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
B = os.path.abspath(os.environ.get("LEANREA_WORK", os.path.join(HERE, "work")))

if len(sys.argv) < 4:
    print("Usage: python3 -I run.py <arm> <task_id> <rep>", file=sys.stderr)
    print("  arms: leanrea | rea | none", file=sys.stderr)
    sys.exit(1)

ARM, TID, REP = sys.argv[1], sys.argv[2], sys.argv[3]
AGENT = os.environ.get("BENCH_AGENT", "claude").lower()
MODEL = os.environ.get("BENCH_MODEL", "sonnet")

task = next(t for t in json.load(open(f"{HERE}/tasks.json")) if t["id"] == TID)
ws = f"{B}/runs/{ARM}-{TID}-{REP}"
shutil.rmtree(ws, ignore_errors=True)
os.makedirs(ws, exist_ok=True)

# Copy benchmark target files using cross-platform python shutil (replaces platform-dependent cp -c)
targets_dir = os.path.join(B, "targets")
for f in ["app.asar", "mac_utils.node", "gh"]:
    src = os.path.join(targets_dir, f)
    if os.path.exists(src):
        shutil.copy2(src, ws)

unpacked = os.path.join(targets_dir, "app.asar.unpacked")
if os.path.exists(unpacked):
    shutil.copytree(unpacked, os.path.join(ws, "app.asar.unpacked"), dirs_exist_ok=True)

# Environment filtering: pass only necessary variables; prevent token leaks from host shell
KEEP = {"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL", "TERM"}
env = {k: v for k, v in os.environ.items() if k in KEEP or k.startswith(("ANTHROPIC_", "CLAUDE_", "GEMINI_", "GOOGLE_", "OPENAI_"))}
env.update(npm_config_cache=os.path.join(ws, ".npm"), GOTELEMETRY="off")

# Deploy skill to standard locations for Claude, Antigravity, and generic agents
claude_skills = os.path.join(ws, ".claude", "skills")
agent_skills = os.path.join(ws, ".agent", "skills")
os.makedirs(claude_skills, exist_ok=True)
os.makedirs(agent_skills, exist_ok=True)

prompt = task["prompt"]

if ARM == "rea":
    rea_src = f"{B}/rea-install/node_modules/rea-agents/skills/reverse-engineer-anything"
    if os.path.exists(rea_src):
        shutil.copytree(rea_src, f"{claude_skills}/reverse-engineer-anything", dirs_exist_ok=True)
        shutil.copytree(rea_src, f"{agent_skills}/reverse-engineer-anything", dirs_exist_ok=True)
    prompt = "/reverse-engineer-anything " + prompt
elif ARM == "leanrea":
    shutil.copytree(f"{REPO}/leanrea", f"{claude_skills}/leanrea", dirs_exist_ok=True)
    shutil.copytree(f"{REPO}/leanrea", f"{agent_skills}/leanrea", dirs_exist_ok=True)
    # Also write top-level SKILL.md into workspace for generic agent discovery
    shutil.copy2(f"{REPO}/SKILL.md", os.path.join(ws, "SKILL.md"))
    prompt = "/leanrea " + prompt

# Configure agent command
custom_cmd = os.environ.get("BENCH_AGENT_CMD")
if custom_cmd:
    # Custom runner command template, e.g. "my-agent --prompt '{prompt}'"
    cmd_str = custom_cmd.format(prompt=prompt, model=MODEL, ws=ws)
    cmd = ["bash", "-c", cmd_str]
elif AGENT == "claude":
    # Sandboxed Claude Code runner
    sandbox = {
        "enabled": True,
        "failIfUnavailable": True,
        "allowUnsandboxedCommands": False,
        "autoAllowBashIfSandboxed": True,
        "filesystem": {"denyRead": ["~/"], "allowRead": [ws]},
        "network": {"allowedDomains": ["registry.npmjs.org"], "strictAllowlist": True}
    }
    cmd = [
        "claude", "-p", "--model", MODEL, "--output-format", "stream-json", "--verbose",
        "--strict-mcp-config", "--no-session-persistence", "--max-budget-usd", "4",
        "--settings", json.dumps({"sandbox": sandbox}),
        "--allowedTools", "Read(./**),Grep,Glob,Edit(./**),Skill,mcp__rea"
    ]
    if ARM == "rea" and os.path.exists(f"{B}/rea-mcp.json"):
        cmd += ["--mcp-config", f"{B}/rea-mcp.json"]
elif AGENT == "gemini":
    # Gemini / Antigravity CLI runner
    cmd = ["gemini", "--model", MODEL, "-p", prompt]
else:
    print(f"Unknown agent: {AGENT}. Set BENCH_AGENT_CMD for custom agents.", file=sys.stderr)
    sys.exit(1)

t0 = time.time()
try:
    p = subprocess.run(cmd, input=prompt if AGENT == "claude" else None, cwd=ws, env=env, capture_output=True, text=True, timeout=1500)
    wall = time.time() - t0
    stdout = p.stdout or ""
    stderr = p.stderr or ""
except subprocess.TimeoutExpired:
    wall = 1500.0
    stdout, stderr = "", "Execution timed out after 1500s"
    p = subprocess.CompletedProcess(cmd, returncode=124, stdout="", stderr=stderr)

r, tools = {"result": stdout[-2000:] + stderr[-2000:], "is_error": (p.returncode != 0)}, []

# Parse structured stream events if output is JSON-stream (e.g. Claude Code stream-json)
for line in stdout.splitlines():
    try:
        ev = json.loads(line)
    except Exception:
        continue
    if ev.get("type") == "result":
        r = ev
    if ev.get("type") == "assistant":
        for c in ev.get("message", {}).get("content", []):
            if c.get("type") == "tool_use":
                n = c["name"]
                tools.append(n if n != "Bash" else "Bash:" + c.get("input", {}).get("command", "")[:60].split()[0] if c.get("input", {}).get("command") else n)

ans = r.get("result") or stdout
hits = {k: bool(re.search(v, ans, re.I)) for k, v in task["key"].items()}
u = r.get("usage", {})
row = {
    "agent": AGENT, "arm": ARM, "task": TID, "rep": REP, "wall_s": round(wall, 1),
    "turns": r.get("num_turns"), "cost": r.get("total_cost_usd"),
    "in": u.get("input_tokens", 0), "cache_w": u.get("cache_creation_input_tokens", 0),
    "cache_r": u.get("cache_read_input_tokens", 0), "out": u.get("output_tokens", 0),
    "score": f"{sum(hits.values())}/{len(hits)}", "miss": [k for k, v in hits.items() if not v],
    "err": r.get("is_error", False), "tools": tools
}

with open(f"{ws}.json", "w") as out_f:
    json.dump({**row, "answer": ans}, out_f, indent=1)

print(json.dumps(row))
