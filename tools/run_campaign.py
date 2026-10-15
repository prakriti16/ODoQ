#!/usr/bin/env python3
"""Run a measurement campaign on the host (stdlib only).

  tools/run_campaign.py campaigns/stage1_smoke.json --dry-run
  sudo -v && tools/run_campaign.py campaigns/stage1_smoke.json

Output: results/<name>_<UTC timestamp>/
  manifest.json       host, software, config snapshot, git state (start + end)
  plan.json           every planned run, in execution order
  runs.jsonl          one line per executed run: factors, time window, load
  runs/<run_id>/      client.jsonl, client.keys, odq-*.pcap
Component logs (proxy, resolver) stay in results/components/ and are sliced
by each run's time window at analysis time. All timestamps share
CLOCK_MONOTONIC with the containers.

Order: blocked randomization. Each repetition visits netem profiles in a
random order; within a profile all cells run in random order. Interleaving
protocols within a block protects against slow drift in machine state.
"""

import argparse
import datetime as dt
import hashlib
import itertools
import json
import os
import random
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINKS = {  # link -> ((container, peer_ip_it_shapes_toward), (container, peer_ip))
    "cp": (("odoq-client", "10.77.1.20"), ("odoq-proxy", "10.77.1.10")),
    "pr": (("odoq-proxy", "10.77.2.30"), ("odoq-resolver", "10.77.2.20")),
    "cr": (("odoq-client", "10.77.3.30"), ("odoq-resolver", "10.77.3.10")),
    "ra": (("odoq-resolver", "10.77.4.40"), ("odoq-auth", "10.77.4.30")),
    "co": (("odoq-client", "10.77.5.50"), ("odoq-odoh-relay", "10.77.5.10")),
    "ot": (("odoq-odoh-relay", "10.77.6.60"), ("odoq-odoh-target", "10.77.6.50")),
    # ODoH target -> auth on link_ra. Only the target end: auth's link_ra
    # interface is already shaped by "ra" (netem applies to the whole device).
    "ta": (("odoq-odoh-target", "10.77.4.40"),),
}
BRIDGES = ["odq-cp", "odq-pr", "odq-cr", "odq-ra", "odq-co", "odq-ot"]
CONTAINERS = ["odoq-client", "odoq-proxy", "odoq-resolver", "odoq-auth",
              "odoq-odoh-relay", "odoq-odoh-target"]
VARIANTS = {  # variant -> (protocol, port on proxy or resolver)
    "doq": ("doq", 853),
    "odoq-persistent": ("odoq", 8853),
    "odoq-per-query": ("odoq", 8854),
    "odoq-legacy": ("odoq", 8855),
    "odoh-h3": ("odoh", 8443),
    "odoh-h2": ("odoh", 8443),   # same relay port, TCP instead of UDP
}
ODOH_TRANSPORT = {"odoh-h3": "h3", "odoh-h2": "h2"}
PADDING = {"none": 0, "rfc8467": 128}


def sh(cmd, check=True, capture=True, timeout=None):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), text=True,
                       capture_output=capture, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {cmd}\n{r.stderr}")
    return r.stdout.strip() if capture else ""


def try_sh(cmd):
    try:
        return sh(cmd, check=False, timeout=30)
    except Exception as e:  # noqa: BLE001
        return f"<error: {e}>"


def dexec(container, *args, check=True, timeout=None):
    return sh(["docker", "exec", container, *args], check=check, timeout=timeout)


# --------------------------------------------------------------------------
# plan
# --------------------------------------------------------------------------

def excluded(cell, rules):
    for rule in rules:
        if all(cell.get(k) in (v if isinstance(v, list) else [v])
               for k, v in rule.items()):
            return True
    return False


def make_plan(c):
    f = c["factors"]
    rng = random.Random(c["seed"])
    keys = ["variant", "conn_mode", "cache", "padding"]
    plan = []
    for rep in range(c["repetitions"]):
        profiles = list(f["netem"])
        rng.shuffle(profiles)
        for prof in profiles:
            cells = [dict(zip(keys, vals), netem=prof)
                     for vals in itertools.product(*(f[k] for k in keys))]
            cells = [x for x in cells if not excluded(x, c.get("exclude", []))]
            rng.shuffle(cells)
            for cell in cells:
                cell["rep"] = rep
                cell["run_id"] = f"r{len(plan):05d}"
                cell["seed"] = rng.randrange(2**31)
                plan.append(cell)
    return plan


# --------------------------------------------------------------------------
# environment
# --------------------------------------------------------------------------

def apply_netem(profile_name, profiles):
    for c in CONTAINERS:
        dexec(c, "/opt/odoq/scripts/netem.sh", "clear")
    prof = profiles[profile_name]
    for link, spec in prof.items():
        half = spec.get("rtt_ms", 0) / 2
        for container, peer in LINKS[link]:
            dexec(container, "/opt/odoq/scripts/netem.sh", "set", peer,
                  f"{half:g}", f"{spec.get('jitter_ms', 0):g}",
                  f"{spec.get('loss_pct', 0):g}")
    state = {c: dexec(c, "/opt/odoq/scripts/netem.sh", "show") for c in CONTAINERS}
    verify_netem(prof, state)
    return state


def verify_netem(prof, state):
    """Fail loudly if any endpoint that should be shaped is not.

    Restarting a container destroys its network namespace and with it every
    qdisc, so netem must be (re)applied after any restart.
    """
    expected = {c: 0 for c in CONTAINERS}
    for link, spec in prof.items():
        if any(spec.get(k, 0) for k in ("rtt_ms", "jitter_ms", "loss_pct")):
            for container, _ in LINKS[link]:
                expected[container] += 1
    for c, n in expected.items():
        got = state[c].count("netem")
        if got != n:
            raise RuntimeError(f"netem check failed on {c}: expected {n} shaped "
                               f"interfaces, found {got}\n{state[c]}")


def flush_resolver_cache():
    for args in (["flush_zone", "."], ["flush_infra", "all"], ["flush_requestlist"]):
        dexec("odoq-resolver", "unbound-control", "-c", "/etc/odoq/unbound.conf",
              *args)


def restart_proxy():
    """Restart proxy and ODoH relay so no upstream connection state (RTT
    estimate, congestion window) carries across netem profiles."""
    sh(["docker", "restart", "odoq-proxy", "odoq-odoh-relay"])
    plog = ROOT / "results/components/proxy.jsonl"
    for _ in range(100):
        if plog.exists():
            txt = plog.read_text()
            if txt.count('"event":"listening"') >= 3:
                time.sleep(1.0)
                return
        time.sleep(0.1)
    raise RuntimeError("proxy did not come back after restart")


CAPTURE_HELPER = "/usr/local/sbin/odoq-capture"  # pins tcpdump to CPUs 13,29


def start_captures(run_dir):
    procs = []
    for br in BRIDGES:
        out = (run_dir / f"{br}.pcap").resolve()
        p = subprocess.Popen(["sudo", "-n", CAPTURE_HELPER, br, str(out)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        procs.append(p)
    time.sleep(0.5)  # let tcpdump attach before traffic starts
    for p in procs:
        if p.poll() is not None:
            raise RuntimeError("tcpdump failed: " + p.stderr.read().decode())
    return procs


def stop_captures(procs):
    time.sleep(0.3)
    for p in procs:
        p.send_signal(signal.SIGINT)
    for p in procs:
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()


def host_snapshot():
    gov = try_sh("cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort | uniq -c")
    return {
        "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "loadavg": Path("/proc/loadavg").read_text().strip(),
        "governor": gov,
        "vms": try_sh("sudo -n virsh list --all"),
        "meminfo": try_sh("free -m"),
    }


def manifest(c, args):
    def h(p):
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    src = {str(p.relative_to(ROOT)): h(p)
           for p in sorted((ROOT / "src").rglob("*.py"))}
    return {
        "campaign": c,
        "campaign_file": str(args.campaign),
        "argv": sys.argv,
        "git_commit": try_sh(f"git -C {ROOT} rev-parse HEAD"),
        "git_dirty": try_sh(f"git -C {ROOT} status --porcelain"),
        "src_sha256": src,
        "configs": {p: Path(ROOT / p).read_text() for p in (
            "config/domains.json", "config/netem_profiles.json",
            "config/unbound.conf", "config/nsd.conf", "docker-compose.yml",
            "requirements.txt", "docker/Dockerfile")},
        "host": {
            "uname": try_sh("uname -a"),
            "os_release": try_sh("cat /etc/os-release"),
            "lscpu": try_sh("lscpu"),
            "cpu_pairs": try_sh("lscpu -e=CPU,CORE"),
            "docker_version": try_sh("docker version --format '{{json .}}'"),
            "netem_module": try_sh("lsmod | grep netem"),
        },
        "image": try_sh("docker image inspect odoq-testbed:stage1 --format '{{.Id}}'"),
        "pip_freeze": try_sh("docker exec odoq-client pip freeze"),
        "unbound_version": try_sh("docker exec odoq-resolver unbound -V"),
        "nsd_version": try_sh("docker exec odoq-auth nsd -v"),
        "containers": try_sh("docker ps --format '{{.Names}} {{.Image}} {{.Status}}'"),
        "start": host_snapshot(),
    }


def preflight(c):
    up = sh("docker ps --format '{{.Names}}'").split()
    missing = [x for x in CONTAINERS if x not in up]
    if missing:
        sys.exit(f"containers not running: {missing}. Run: docker compose up -d")
    dexec("odoq-client", "python3", "-c", "import odoq.client")
    gov = try_sh("cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort -u")
    if gov.strip() != "performance":
        print(f"WARNING: CPU governor is '{gov}'. Run scripts/host_prep.sh first.")
    if c.get("capture") and subprocess.run(
            ["sudo", "-n", CAPTURE_HELPER, "--check"],
            capture_output=True).returncode != 0:
        sys.exit("capture helper missing: run scripts/install_capture_helper.sh "
                 "once (or set \"capture\": false)")


# --------------------------------------------------------------------------
# main loop
# --------------------------------------------------------------------------

def client_cmd(cell, c, out_dir_in_container, qnames):
    proto, port = VARIANTS[cell["variant"]]
    cmd = ["docker", "exec", "odoq-client", "python3", "-m", "odoq.client",
           "--protocol", proto, "--mode", cell["conn_mode"],
           "--ca", "/certs/ca.pem", "--qtype", c["qtype"],
           "--per-domain", str(c["per_domain"]), "--gap-ms", str(c["gap_ms"]),
           "--seed", str(cell["seed"]), "--run-id", cell["run_id"],
           "--pad-query-block", str(PADDING[cell["padding"]]),
           "--out", f"{out_dir_in_container}/client.jsonl",
           "--secrets-log", f"{out_dir_in_container}/client.keys"]
    if proto == "doq":
        cmd += ["--target-host", "10.77.3.30", "--target-port", str(port)]
    elif proto == "odoh":
        cmd += ["--transport", ODOH_TRANSPORT[cell["variant"]],
                "--target-host", "10.77.6.60", "--target-port", "8553",
                "--proxy-host", "10.77.5.50", "--proxy-port", "8443",
                "--proxy-name", "proxy.odoq.test",
                "--target-pub", "/certs/hpke_pub.bin"]
    else:
        cmd += ["--target-host", "10.77.2.30", "--target-port", "8853",
                "--proxy-host", "10.77.1.20", "--proxy-port", str(port),
                "--target-pub", "/certs/target_pub.pem"]
    cmd += ["--cache-bust"] if cell["cache"] == "miss" else ["--prewarm"]
    for q in qnames:
        cmd += ["--qname", q]
    return cmd


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("campaign", type=Path)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=None, help="run only N runs")
    args = ap.parse_args()
    os.chdir(ROOT)
    c = json.loads(args.campaign.read_text())
    plan = make_plan(c)
    if args.limit:
        plan = plan[: args.limit]
    qnames = Path("config/qnames.txt").read_text().split()
    n_q = len(plan) * len(qnames) * c["per_domain"]
    print(f"{len(plan)} runs, {n_q} timed queries")
    if args.dry_run:
        by = {}
        for x in plan:
            k = (x["variant"], x["netem"])
            by[k] = by.get(k, 0) + 1
        for k, v in sorted(by.items()):
            print(f"  {k[0]:16} {k[1]:12} {v} runs")
        return

    preflight(c)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    camp_dir = Path("results") / f"{c['name']}_{stamp}"
    (camp_dir / "runs").mkdir(parents=True)
    profiles = json.loads(Path("config/netem_profiles.json").read_text())
    man = manifest(c, args)
    (camp_dir / "manifest.json").write_text(json.dumps(man, indent=2))
    (camp_dir / "plan.json").write_text(json.dumps(plan, indent=1))
    runs_log = open(camp_dir / "runs.jsonl", "a", buffering=1)

    current_profile, netem_state = None, None
    t_campaign = time.monotonic()
    try:
        for i, cell in enumerate(plan):
            if cell["netem"] != current_profile:
                # restart FIRST: a restart wipes the container's qdiscs
                if c.get("restart_proxy_on_profile_change", True):
                    restart_proxy()
                netem_state = apply_netem(cell["netem"], profiles)
                current_profile = cell["netem"]
            run_dir = camp_dir / "runs" / cell["run_id"]
            run_dir.mkdir()
            flush_resolver_cache()
            caps = start_captures(run_dir) if c.get("capture") else []
            rec = dict(cell, loadavg_before=Path("/proc/loadavg").read_text().strip(),
                       netem_state=netem_state)
            rec["t_start_ns"] = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            r = subprocess.run(client_cmd(cell, c, f"/{camp_dir}/runs/{cell['run_id']}",
                                          qnames),
                               text=True, capture_output=True)
            rec["t_end_ns"] = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            stop_captures(caps)
            rec["client_rc"] = r.returncode
            rec["client_summary"] = r.stdout.strip().splitlines()[-1:] if r.stdout else []
            if r.returncode != 0:
                rec["client_stderr"] = r.stderr[-2000:]
            rec["loadavg_after"] = Path("/proc/loadavg").read_text().strip()
            runs_log.write(json.dumps(rec) + "\n")
            el = time.monotonic() - t_campaign
            eta = el / (i + 1) * (len(plan) - i - 1)
            print(f"[{i + 1}/{len(plan)}] {cell['run_id']} {cell['variant']:16} "
                  f"{cell['conn_mode']:6} {cell['cache']:4} {cell['netem']:12} "
                  f"{cell['padding']:8} rc={r.returncode} "
                  f"{rec['client_summary']}  eta {eta / 60:.0f} min", flush=True)
    finally:
        runs_log.close()
        for ct in CONTAINERS:
            try_sh(f"docker exec {ct} /opt/odoq/scripts/netem.sh clear")
        man["end"] = host_snapshot()
        (camp_dir / "manifest.json").write_text(json.dumps(man, indent=2))
        uid, gid = os.getuid(), os.getgid()
        try_sh(f"docker exec odoq-client chown -R {uid}:{gid} /{camp_dir}")
        print(f"campaign dir: {camp_dir}")


if __name__ == "__main__":
    main()
