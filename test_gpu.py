"""GPU readers. Run: python test_gpu.py (needs psutil, e.g. inside the gaugery image)."""
import os
import tempfile

from collectors import parse_nvidia, parse_pmon, amd_gpus
g = parse_nvidia("0, NVIDIA GeForce RTX 3090, 42, 1024, 24576, 61, 120.5, 3, 18\n1, Tesla T4, [N/A], 0, 15360, 40, [N/A], [N/A], [N/A]\n")
assert g[0] == {"id": "nvidia0", "name": "NVIDIA GeForce RTX 3090", "util": 42.0, "mem_used": 1024 * 2**20,
                "mem_total": 24576 * 2**20, "temp": 61.0, "power": 120.5, "enc": 3.0, "dec": 18.0}, g[0]
assert g[1]["util"] is None and g[1]["power"] is None
d = tempfile.mkdtemp(); os.makedirs(f"{d}/card1/device"); os.makedirs(f"{d}/card0/device"); os.makedirs(f"{d}/card1-DP-1")
for n, v in (("gpu_busy_percent", "37"), ("mem_info_vram_used", "512"), ("mem_info_vram_total", "2048")):
    open(f"{d}/card1/device/{n}", "w").write(v + "\n")
a = amd_gpus(d)
assert a == [{"id": "amd1", "name": "AMD GPU 1", "util": 37.0, "mem_used": 512.0, "mem_total": 2048.0, "temp": None, "power": None}], a

pm = parse_pmon("""# gpu         pid   type     sm    mem    enc    dec    jpg    ofa     fb   ccpm    command
# Idx           #    C/G      %      %      %      %      %      %     MB     MB    name
    0       4321     G      2      1      -      -      -      -     88      0    Xorg
    0       1234     C     71     40      -      -      -      -   5120      0    python3 train.py
    1       5555   C+G      -      -     35     12      -      -    300      0    ffmpeg
    1          -     -      -      -      -      -      -      -      -      -    -
""")
assert [p["pid"] for p in pm] == [1234, 4321, 5555], pm
assert pm[0] == {"gpu": "nvidia0", "pid": 1234, "type": "compute", "name": "python3 train.py", "sm": 71.0,
                 "enc": None, "dec": None, "mem": 5120 * 2**20}, pm[0]
assert pm[2]["type"] == "compute+graphics" and pm[2]["enc"] == 35.0 and pm[2]["sm"] is None
assert parse_pmon("") == []
print("ok")
