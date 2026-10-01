"""Metric collectors for Monitorr.

Collector.sample() returns (series, state):
  series: flat {key: number} used for charts and history
  state:  richer objects (drives, containers, processes) for tables
"""
import http.client
import json
import os
import platform
import shutil
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

import psutil

SKIP_FS = {
    "tmpfs", "devtmpfs", "devpts", "overlay", "squashfs", "proc", "sysfs", "cgroup",
    "cgroup2", "securityfs", "pstore", "bpf", "debugfs", "tracefs", "configfs",
    "fusectl", "mqueue", "hugetlbfs", "autofs", "binfmt_misc", "rpc_pipefs", "nsfs",
    "efivarfs", "ramfs", "selinuxfs", "nfsd", "fuse.gvfsd-fuse", "fuse.portal",
    "fuse.lxcfs", "fuse.snapfuse",
}
NETWORK_FS = {
    "nfs", "nfs4", "cifs", "smb3", "smbfs", "sshfs", "fuse.sshfs", "glusterfs",
    "9p", "fuse.rclone", "davfs", "fuse.s3fs", "ceph",
}
SKIP_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker",
                 "/var/snap", "/var/lib/snapd", "/var/lib/kubelet", "/var/lib/containers")
ALLOW_PREFIXES = ("/run/media",)
VIRTUAL_NICS = ("lo", "veth", "br-", "docker", "virbr", "vnet", "cali", "flannel", "cni")
NOT_DISKS = ("loop", "ram", "zram", "sr", "fd", "nbd", "dm-", "md")
IGNORE_MOUNTS = {m.strip() for m in os.environ.get("IGNORE_MOUNTS", "").split(",") if m.strip()}
# Docker is reached through a socket proxy that only allows what Monitorr uses (tcp://docker-proxy:2375),
# or directly through its socket (unix:///var/run/docker.sock) on a plain systemd install.
DOCKER_HOST = os.environ.get("DOCKER_HOST") or "unix://" + os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
# Drive health needs raw disk access (privileges), so it's off unless asked for.
SMART_ENABLED = os.environ.get("SMART", "").lower() in ("1", "true", "yes", "on")
# When running in a container, the host's / is mounted here (e.g. /host).
HOST_ROOT = os.environ.get("HOST_ROOT", "").rstrip("/")


def hp(path):
    """Translate a host path to where it is visible to this process."""
    if not HOST_ROOT:
        return path
    return HOST_ROOT + (path if path != "/" else "")


class _Part:
    __slots__ = ("device", "mountpoint", "fstype", "opts")

    def __init__(self, device, mountpoint, fstype, opts):
        self.device, self.mountpoint, self.fstype, self.opts = device, mountpoint, fstype, opts


def _unescape(v):
    return (v.replace(r"\040", " ").replace(r"\011", "\t")
            .replace(r"\012", "\n").replace(r"\134", "\\"))


def list_mounts():
    """Host mounts: read init's mount table in a container (needs pid: host)."""
    if not HOST_ROOT:
        return psutil.disk_partitions(all=True)
    parts = []
    try:
        with open("/proc/1/mounts") as f:
            lines = f.readlines()
        prefix = ""
    except OSError:
        # Fallback: our own mount table, where the host's mounts appear under HOST_ROOT
        with open("/proc/self/mounts") as f:
            lines = f.readlines()
        prefix = HOST_ROOT
    for line in lines:
        bits = line.split()
        if len(bits) < 4:
            continue
        mp = _unescape(bits[1])
        if prefix:
            if mp != prefix and not mp.startswith(prefix + "/"):
                continue
            mp = mp[len(prefix):] or "/"
        parts.append(_Part(_unescape(bits[0]), mp, bits[2], bits[3]))
    return parts


def _passwd():
    users = {}
    try:
        with open(hp("/etc/passwd")) as f:
            for line in f:
                b = line.split(":")
                if len(b) > 2 and b[2].isdigit():
                    users[int(b[2])] = b[0]
    except OSError:
        pass
    return users


def _under(path, prefixes):
    return any(path == p or path.startswith(p + "/") for p in prefixes)


def whole_disks():
    try:
        names = os.listdir("/sys/block")
    except OSError:
        return []
    return sorted(n for n in names if not n.startswith(NOT_DISKS))


def _disk_for(name, depth=0):
    """Walk partitions, LVM and RAID down to the physical disk name."""
    if depth > 4:
        return None
    sysp = f"/sys/class/block/{name}"
    if not os.path.exists(sysp):
        return None
    if os.path.exists(sysp + "/partition"):
        return os.path.basename(os.path.dirname(os.path.realpath(sysp)))
    slaves = sysp + "/slaves"
    if os.path.isdir(slaves):
        found = sorted(os.listdir(slaves))
        if found:
            return _disk_for(found[0], depth + 1)
    return name


def resolve_disk(device):
    if not device.startswith("/dev/"):
        return None
    try:
        return _disk_for(os.path.basename(os.path.realpath(hp(device))))
    except OSError:
        return None


def _stat_mount(path):
    u = psutil.disk_usage(path)
    st = os.statvfs(path)
    inodes = 100.0 * (1 - st.f_ffree / st.f_files) if st.f_files else None
    return u, inodes


def host_info():
    os_name = platform.system()
    try:
        with open(hp("/etc/os-release")) as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    cpu_model = platform.processor() or ""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    virt = "unknown"
    if shutil.which("systemd-detect-virt") and not HOST_ROOT:
        try:
            virt = subprocess.run(["systemd-detect-virt"], capture_output=True,
                                  text=True, timeout=3).stdout.strip() or "none"
        except Exception:
            pass
    else:
        virt = _virt_from_dmi()
    hostname = socket.gethostname()
    if HOST_ROOT:
        try:
            with open(hp("/etc/hostname")) as f:
                hostname = f.read().strip() or hostname
        except OSError:
            pass
    return {
        "hostname": hostname,
        "os": os_name,
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu_model": cpu_model,
        "cores": psutil.cpu_count() or 1,
        "physical_cores": psutil.cpu_count(logical=False),
        "mem_total": psutil.virtual_memory().total,
        "swap_total": psutil.swap_memory().total,
        "boot_time": psutil.boot_time(),
        "virt": virt,
    }


def _virt_from_dmi():
    def rd(n):
        try:
            with open(f"/sys/class/dmi/id/{n}") as f:
                return f.read().strip().lower()
        except OSError:
            return ""
    blob = " ".join(rd(n) for n in ("sys_vendor", "product_name", "board_vendor"))
    for needle, name in (("microsoft", "microsoft"), ("qemu", "qemu"), ("kvm", "kvm"),
                         ("vmware", "vmware"), ("virtualbox", "oracle"), ("innotek", "oracle"),
                         ("xen", "xen"), ("proxmox", "kvm")):
        if needle in blob:
            return name
    return "none" if blob else "unknown"


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=5):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def docker_connection(timeout=5):
    if DOCKER_HOST.startswith("tcp://"):
        host, _, port = DOCKER_HOST[6:].rstrip("/").partition(":")
        return http.client.HTTPConnection(host, int(port or 2375), timeout=timeout)
    return _UnixHTTP(DOCKER_HOST.removeprefix("unix://"), timeout)


def docker_reachable():
    return DOCKER_HOST.startswith("tcp://") or os.path.exists(DOCKER_HOST.removeprefix("unix://"))


class DockerWatcher(threading.Thread):
    """Polls Docker every few seconds (never blocks the main sampler)."""

    def __init__(self, interval=5):
        super().__init__(daemon=True)
        self.interval = interval
        self.containers, self.error, self._prev = [], None, {}
        self.available = docker_reachable()

    def _get(self, path):
        conn = docker_connection()
        try:
            conn.request("GET", path, headers={"Host": "docker"})
            r = conn.getresponse()
            body = r.read()
        finally:
            conn.close()
        if r.status >= 400:
            raise RuntimeError(f"Docker API {r.status} for {path}")
        return json.loads(body)

    def run(self):
        while True:
            if docker_reachable():
                try:
                    self.poll()
                    self.available, self.error = True, None
                except PermissionError:
                    self.available, self.error = False, "permission denied on docker.sock"
                except (ConnectionError, socket.gaierror, TimeoutError) as e:
                    self.available, self.error = False, f"can't reach {DOCKER_HOST} ({type(e).__name__})"
                except Exception as e:  # noqa: BLE001
                    self.error = str(e)
            else:
                self.available = False
            time.sleep(self.interval)

    def poll(self):
        ncpu = psutil.cpu_count() or 1
        total_mem = psutil.virtual_memory().total
        out = []
        for c in self._get("/containers/json?all=1"):
            cid = c["Id"]
            name = c["Names"][0].lstrip("/") if c.get("Names") else cid[:12]
            item = {"id": cid[:12], "name": name, "image": c.get("Image"),
                    "state": c.get("State"), "status": c.get("Status"), "cpu": None,
                    "mem": None, "mem_limit": None, "restarts": 0, "health": None,
                    "exit_code": None}
            try:
                ins = self._get(f"/containers/{cid}/json")
                st = ins.get("State", {})
                item["restarts"] = ins.get("RestartCount", 0)
                item["health"] = (st.get("Health") or {}).get("Status")
                item["exit_code"] = st.get("ExitCode")
            except Exception:  # noqa: BLE001
                pass
            if c.get("State") == "running":
                try:
                    stt = self._get(f"/containers/{cid}/stats?stream=false&one-shot=true")
                    cs = stt.get("cpu_stats", {})
                    cu = cs.get("cpu_usage", {}).get("total_usage", 0)
                    sy = cs.get("system_cpu_usage", 0)
                    online = cs.get("online_cpus") or ncpu
                    prev = self._prev.get(cid)
                    if prev and sy > prev[1]:
                        item["cpu"] = max(0.0, (cu - prev[0]) / (sy - prev[1]) * online * 100)
                    self._prev[cid] = (cu, sy)
                    ms = stt.get("memory_stats", {})
                    stats = ms.get("stats", {})
                    inactive = stats.get("inactive_file", stats.get("total_inactive_file", 0))
                    item["mem"] = max(0, ms.get("usage", 0) - inactive)
                    lim = ms.get("limit")
                    item["mem_limit"] = lim if lim and lim < total_mem else total_mem
                except Exception:  # noqa: BLE001
                    pass
            out.append(item)
        out.sort(key=lambda x: (x["state"] != "running", x["name"]))
        self.containers = out


def parse_smart(j):
    r = {"model": j.get("model_name"), "status": "unavailable",
         "temp": (j.get("temperature") or {}).get("current"),
         "hours": (j.get("power_on_time") or {}).get("hours"),
         "reallocated": None, "pending": None, "wear": None, "media_errors": None,
         "reason": None}
    for a in (j.get("ata_smart_attributes") or {}).get("table", []):
        raw = (a.get("raw") or {}).get("value")
        if a.get("id") == 5:
            r["reallocated"] = raw
        elif a.get("id") == 197:
            r["pending"] = raw
    nv = j.get("nvme_smart_health_information_log")
    if nv:
        r["wear"] = nv.get("percentage_used")
        r["media_errors"] = nv.get("media_errors")
        r["temp"] = r["temp"] or nv.get("temperature")
    passed = (j.get("smart_status") or {}).get("passed")
    if passed is False:
        r["status"] = "failed"
    elif passed is True:
        bad = ((r["reallocated"] or 0) > 0 or (r["pending"] or 0) > 0
               or (r["wear"] or 0) >= 90 or (r["media_errors"] or 0) > 0)
        r["status"] = "warning" if bad else "ok"
    else:
        msgs = (j.get("smartctl") or {}).get("messages") or []
        r["reason"] = msgs[0].get("string") if msgs else "SMART not supported on this device"
    return r


class SmartWatcher(threading.Thread):
    """Runs smartctl on every physical disk every 10 minutes (needs root)."""

    def __init__(self, interval=600):
        super().__init__(daemon=True)
        self.interval = interval
        self.enabled = SMART_ENABLED
        self.available = SMART_ENABLED and shutil.which("smartctl") is not None
        self.data = {}

    def run(self):
        while self.available:
            res = {}
            for d in whole_disks():
                try:
                    p = subprocess.run(["smartctl", "--json", "-a", f"/dev/{d}"],
                                       capture_output=True, text=True, timeout=30)
                    res[d] = parse_smart(json.loads(p.stdout or "{}"))
                except Exception:  # noqa: BLE001
                    continue
            self.data = res
            time.sleep(self.interval)


NVIDIA_QUERY = ("index,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,"
                "utilization.encoder,utilization.decoder")


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None  # nvidia-smi prints "[N/A]" or "[Not Supported]" for missing readings


def parse_nvidia(text):
    """nvidia-smi --query-gpu=NVIDIA_QUERY --format=csv,noheader,nounits -> list of GPU dicts."""
    out = []
    for line in text.splitlines():
        p = [x.strip() for x in line.split(",")]
        if len(p) != 9:
            continue
        used, total = _f(p[3]), _f(p[4])
        out.append({"id": f"nvidia{p[0]}", "name": p[1][:100], "util": _f(p[2]),
                    "mem_used": used * 2**20 if used is not None else None,
                    "mem_total": total * 2**20 if total is not None else None,
                    "temp": _f(p[5]), "power": _f(p[6]), "enc": _f(p[7]), "dec": _f(p[8])})
    return out


PROC_TYPES = {"C": "compute", "G": "graphics", "C+G": "compute+graphics"}


def parse_pmon(text):
    """nvidia-smi pmon -c 1 -s um -> processes on NVIDIA GPUs. Columns are read from the header,
    since newer drivers add some (jpg, ofa, ccpm); idle GPUs print a row of dashes."""
    cols, out = None, []
    for line in text.splitlines():
        if line.startswith("# gpu"):
            cols = line[1:].split()
            continue
        if line.startswith("#") or not cols:
            continue
        p = line.split(None, len(cols) - 1)
        if len(p) != len(cols) or not p[1].isdigit():
            continue
        r = dict(zip(cols, p))
        fb = _f(r.get("fb"))
        out.append({"gpu": f"nvidia{r['gpu']}", "pid": int(r["pid"]), "type": PROC_TYPES.get(r.get("type"), "other"),
                    "name": r.get("command", "").strip()[:100], "sm": _f(r.get("sm")),
                    "enc": _f(r.get("enc")), "dec": _f(r.get("dec")), "mem": fb * 2**20 if fb is not None else None})
    out.sort(key=lambda x: (-(x["sm"] or 0), -(x["mem"] or 0)))
    return out[:50]


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def amd_gpus(root="/sys/class/drm"):
    """AMD cards through the amdgpu driver's sysfs files (temperature already comes from hwmon)."""
    out = []
    try:
        cards = sorted(c for c in os.listdir(root) if c.startswith("card") and c[4:].isdigit())
    except OSError:
        return out
    for c in cards:
        dev = f"{root}/{c}/device"
        busy = _f(_read(f"{dev}/gpu_busy_percent"))
        if busy is None:
            continue  # not amdgpu
        out.append({"id": f"amd{c[4:]}", "name": f"AMD GPU {c[4:]}", "util": busy,
                    "mem_used": _f(_read(f"{dev}/mem_info_vram_used")),
                    "mem_total": _f(_read(f"{dev}/mem_info_vram_total")), "temp": None, "power": None})
    return out


class GpuWatcher(threading.Thread):
    """Reads NVIDIA (nvidia-smi) and AMD (sysfs) GPUs every few seconds, off the main sampler,
    because nvidia-smi can take a few hundred milliseconds.
    ponytail: no Intel; its busy counters need perf/root access (intel_gpu_top). Add if asked."""

    def __init__(self, interval=5):
        super().__init__(daemon=True)
        self.interval = interval
        self.smi = shutil.which("nvidia-smi")
        self.gpus, self.procs = [], []

    def _smi(self, *args):
        try:
            return subprocess.run([self.smi, *args], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.TimeoutExpired):
            return ""

    def poll(self):
        gpus, procs = [], []
        if self.smi:
            gpus = parse_nvidia(self._smi(f"--query-gpu={NVIDIA_QUERY}", "--format=csv,noheader,nounits"))
            # needs the host's process list (pid: host in Docker); on WSL/Windows it is always empty
            procs = parse_pmon(self._smi("pmon", "-c", "1", "-s", "um")) if gpus else []
        return gpus + amd_gpus(), procs

    def run(self):
        while True:
            self.gpus, self.procs = self.poll()
            if not self.gpus and not self.smi:
                return  # nothing to watch on this machine; GPUs don't appear while running
            time.sleep(self.interval)


class _Nic:
    __slots__ = ("bytes_recv", "bytes_sent")

    def __init__(self, rx, tx):
        self.bytes_recv, self.bytes_sent = rx, tx


def host_net_counters():
    """Traffic per interface of the host's network, not this container's.
    With the host's process list visible (pid: host), PID 1 is the host's init and
    /proc/1/net/dev shows the host's interfaces, so the agent needs no host networking."""
    if HOST_ROOT:
        try:
            out = {}
            with open("/proc/1/net/dev") as f:
                for line in f.readlines()[2:]:
                    name, _, rest = line.partition(":")
                    v = rest.split()
                    out[name.strip()] = _Nic(int(v[0]), int(v[8]))
            return out
        except (OSError, ValueError, IndexError):
            pass
    return psutil.net_io_counters(pernic=True)


class Collector:
    def __init__(self):
        self._t = time.time()
        self._net, self._disk = {}, {}
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="stat")
        self._hung = {}  # mountpoint -> future still stuck on a dead mount
        self.docker = DockerWatcher()
        self.smart = SmartWatcher()
        self.gpu = GpuWatcher()
        self.cores = psutil.cpu_count() or 1

    def start(self):
        self.docker.start()
        self.smart.start()
        self.gpu.start()
        psutil.cpu_times_percent(interval=None)
        psutil.cpu_percent(percpu=True)
        self._rates(time.time(), prime=True)

    def _rates(self, now, prime=False):
        dt = max(now - self._t, 1e-3)
        self._t = now
        s = {}
        tot_rx = tot_tx = 0.0
        for nic, c in host_net_counters().items():
            if nic.startswith(VIRTUAL_NICS):
                continue
            p = self._net.get(nic)
            self._net[nic] = c
            if p and not prime:
                rx = max(0.0, (c.bytes_recv - p.bytes_recv) / dt)
                tx = max(0.0, (c.bytes_sent - p.bytes_sent) / dt)
                s[f"net:{nic}:rx"], s[f"net:{nic}:tx"] = rx, tx
                tot_rx += rx
                tot_tx += tx
        disks = set(whole_disks())
        tot_r = tot_w = 0.0
        for name, c in (psutil.disk_io_counters(perdisk=True) or {}).items():
            if name not in disks:
                continue
            p = self._disk.get(name)
            self._disk[name] = c
            if p and not prime:
                r = max(0.0, (c.read_bytes - p.read_bytes) / dt)
                w = max(0.0, (c.write_bytes - p.write_bytes) / dt)
                s[f"disk:{name}:r"], s[f"disk:{name}:w"] = r, w
                if hasattr(c, "busy_time"):
                    s[f"disk:{name}:util"] = min(100.0, max(0.0, (c.busy_time - p.busy_time) / (dt * 10)))
                tot_r += r
                tot_w += w
        if not prime:
            s["net:total:rx"], s["net:total:tx"] = tot_rx, tot_tx
            s["disk:total:r"], s["disk:total:w"] = tot_r, tot_w
        return s

    def _temps(self):
        out = {}
        try:
            sensors = psutil.sensors_temperatures() or {}
        except Exception:  # noqa: BLE001
            return out
        preferred = ("coretemp", "k10temp", "zenpower", "cpu_thermal", "nvme", "acpitz")
        for chip in sorted(sensors, key=lambda c: preferred.index(c) if c in preferred else 99):
            for e in sensors[chip]:
                if e.current is None or e.current <= 0:
                    continue
                label = e.label or ""
                if chip == "coretemp" and label.startswith("Core "):
                    continue  # package temp is enough; keeps the chart readable
                if chip == "coretemp":
                    name = "CPU package"
                elif chip in ("k10temp", "zenpower"):
                    name = f"CPU {label}".strip()
                elif chip == "nvme":
                    name = "NVMe" if label in ("", "Composite") else f"NVMe {label}"
                elif chip == "acpitz":
                    name = "Board"
                else:
                    name = f"{chip} {label}".strip()
                base, n = name, 2
                while name in out:
                    name, n = f"{base} {n}", n + 1
                out[name] = e.current
                if len(out) >= 8:
                    return out
        return out

    def _drives(self):
        entries, seen = [], set()
        for p in list_mounts():
            mp = p.mountpoint
            if p.fstype in SKIP_FS or mp in IGNORE_MOUNTS:
                continue
            if _under(mp, SKIP_PREFIXES) and not _under(mp, ALLOW_PREFIXES):
                continue
            network = p.fstype in NETWORK_FS
            if not network and not p.device.startswith("/"):
                continue
            if p.device in seen:  # bind mounts / btrfs subvolumes of an already listed device
                continue
            seen.add(p.device)
            entries.append(p)

        futures = {}
        for p in entries:
            stuck = self._hung.get(p.mountpoint)
            if stuck is not None and not stuck.done():
                continue
            futures[p.mountpoint] = self._pool.submit(_stat_mount, hp(p.mountpoint))

        drives = []
        for p in entries:
            mp = p.mountpoint
            d = {"mount": mp, "device": p.device, "fs": p.fstype,
                 "network": p.fstype in NETWORK_FS,
                 "readonly": "ro" in p.opts.split(","),
                 "disk": None if p.fstype in NETWORK_FS else resolve_disk(p.device),
                 "status": "ok"}
            fut = futures.get(mp)
            if fut is None:
                d["status"] = "unresponsive"
            else:
                try:
                    u, inodes = fut.result(timeout=2.5)
                    self._hung.pop(mp, None)
                    d.update(total=u.total, used=u.used, free=u.free, pct=u.percent,
                             inodes_pct=inodes)
                except FutureTimeout:
                    self._hung[mp] = fut
                    d["status"] = "unresponsive"
                except OSError as e:
                    d["status"] = "error"
                    d["error"] = e.strerror or str(e)
            drives.append(d)
        return drives

    def _processes(self):
        procs = []
        attrs = ["pid", "name", "username", "cpu_percent", "memory_info", "num_threads"]
        if HOST_ROOT:
            attrs.append("uids")
            if not hasattr(self, "_users") or time.time() - self._users_at > 300:
                self._users, self._users_at = _passwd(), time.time()
        for pr in psutil.process_iter(attrs):
            i = pr.info
            if i["memory_info"] is None:
                continue
            user = i["username"]
            if HOST_ROOT and i.get("uids"):
                user = self._users.get(i["uids"].real, str(i["uids"].real))
            procs.append({"pid": i["pid"], "name": i["name"], "user": user,
                          "cpu": i["cpu_percent"] or 0.0, "mem": i["memory_info"].rss,
                          "threads": i["num_threads"]})
        by_cpu = sorted(procs, key=lambda x: x["cpu"], reverse=True)[:15]
        by_mem = sorted(procs, key=lambda x: x["mem"], reverse=True)[:15]
        merged = {p["pid"]: p for p in by_cpu + by_mem}
        return list(merged.values()), len(procs)

    def sample(self):
        now = time.time()
        s = {}
        ct = psutil.cpu_times_percent(interval=None)
        parts = {
            "user": ct.user, "system": ct.system, "iowait": getattr(ct, "iowait", 0.0),
            "irq": getattr(ct, "irq", 0.0) + getattr(ct, "softirq", 0.0),
            "nice": ct.nice, "steal": getattr(ct, "steal", 0.0),
        }
        for k, v in parts.items():
            s[f"cpu:{k}"] = v
        s["cpu:total"] = min(100.0, sum(parts.values()))
        for i, v in enumerate(psutil.cpu_percent(percpu=True)):
            s[f"core:{i}"] = v
        s["load:1"], s["load:5"], s["load:15"] = os.getloadavg()

        vm = psutil.virtual_memory()
        s["mem:used"], s["mem:free"] = vm.used, vm.free
        s["mem:cached"] = getattr(vm, "cached", 0)
        s["mem:buffers"] = getattr(vm, "buffers", 0)
        s["mem:pct"] = vm.percent
        sw = psutil.swap_memory()
        s["swap:used"], s["swap:free"], s["swap:pct"], s["swap:total"] = sw.used, sw.free, sw.percent, sw.total

        s.update(self._rates(now))
        temps = self._temps()
        gpus = self.gpu.gpus
        for g in gpus:
            if g["temp"] is not None:  # NVIDIA's driver has no hwmon sensor; AMD's is already in temps
                temps[f"GPU {g['id'][6:]}" if len(gpus) > 1 else "GPU"] = g["temp"]
            for k in ("util", "enc", "dec"):
                if g.get(k) is not None:
                    s[f"gpu:{g['id']}:{k}"] = g[k]
            if g["mem_used"] is not None and g["mem_total"]:
                s[f"gpu:{g['id']}:mem"] = 100 * g["mem_used"] / g["mem_total"]
        for k, v in temps.items():
            s[f"temp:{k}"] = v

        drives = self._drives()
        smart = self.smart.data
        for d in drives:
            d["smart"] = smart.get(d["disk"]) if d["disk"] else None
            if d.get("pct") is not None:
                s[f"drive:{d['mount']}:pct"] = d["pct"]
                s[f"drive:{d['mount']}:used"] = d["used"]

        containers = self.docker.containers
        for c in containers:
            if c["state"] == "running":
                if c["cpu"] is not None:
                    s[f"ctr:{c['name']}:cpu"] = c["cpu"]
                if c["mem"] is not None:
                    s[f"ctr:{c['name']}:mem"] = c["mem"]

        procs, nprocs = self._processes()
        state = {
            "drives": drives,
            "containers": containers,
            "docker": {"available": self.docker.available, "error": self.docker.error},
            "smart_available": self.smart.available,
            "smart_enabled": self.smart.enabled,
            "processes": procs,
            "process_count": nprocs,
            "temps": temps,
            "gpus": gpus,
            "gpu_procs": self.gpu.procs,
        }
        return s, state
