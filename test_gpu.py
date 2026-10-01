"""GPU readers. Run: python test_gpu.py (needs psutil, e.g. inside the monitorr image)."""
import os
import tempfile

from collectors import parse_nvidia, amd_gpus
g = parse_nvidia("0, NVIDIA GeForce RTX 3090, 42, 1024, 24576, 61, 120.5\n1, Tesla T4, [N/A], 0, 15360, 40, [N/A]\n")
assert g[0] == {"id": "nvidia0", "name": "NVIDIA GeForce RTX 3090", "util": 42.0, "mem_used": 1024 * 2**20,
                "mem_total": 24576 * 2**20, "temp": 61.0, "power": 120.5}, g[0]
assert g[1]["util"] is None and g[1]["power"] is None
d = tempfile.mkdtemp(); os.makedirs(f"{d}/card1/device"); os.makedirs(f"{d}/card0/device"); os.makedirs(f"{d}/card1-DP-1")
for n, v in (("gpu_busy_percent", "37"), ("mem_info_vram_used", "512"), ("mem_info_vram_total", "2048")):
    open(f"{d}/card1/device/{n}", "w").write(v + "\n")
a = amd_gpus(d)
assert a == [{"id": "amd1", "name": "AMD GPU 1", "util": 37.0, "mem_used": 512.0, "mem_total": 2048.0, "temp": None, "power": None}], a
print("ok")
