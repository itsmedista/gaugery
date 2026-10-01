"""Memory-module parser. Run: python test_hardware.py (needs psutil, e.g. inside the monitorr image)."""
from collectors import parse_dimms, hardware


def dimm(size, mtype, speed, configured, strings, ext=0):
    """One SMBIOS type 17 record; strings are locator, bank, maker, serial, part."""
    f = bytearray(0x28)
    f[0], f[1] = 17, 0x28
    f[0x0C:0x0E] = size.to_bytes(2, "little")
    f[0x12] = mtype
    f[0x15:0x17] = speed.to_bytes(2, "little")
    f[0x1C:0x20] = ext.to_bytes(4, "little")
    f[0x20:0x22] = configured.to_bytes(2, "little")
    if strings:
        f[0x10], f[0x11], f[0x17], f[0x18], f[0x1A] = 1, 2, 3, 4, 5
    return bytes(f) + (b"\0".join(strings) + b"\0\0" if strings else b"\0\0")


table = (bytes([0, 4, 0, 0]) + b"\0\0"  # a BIOS record without strings: skipped
         + dimm(16384, 0x1A, 3200, 2933, [b"DIMM_A1", b"BANK 0", b"Samsung", b"SERIAL-SECRET", b"M378A2K43CB1"])
         + dimm(0, 0x02, 0, 0, [])  # empty slot
         + dimm(0x7FFF, 0x22, 4800, 0, [b"DIMM_B1", b"BANK 1", b"Kingston", b"X", b"KF548"], ext=65536)
         + bytes([127, 4, 0, 0]) + b"\0\0")
d = parse_dimms(table)
assert len(d) == 3, d
assert d[0] == {"slot": "DIMM_A1", "size": 16 * 2**30, "type": "DDR4", "speed": 3200, "configured": 2933,
                "maker": "Samsung", "part": "M378A2K43CB1"}, d[0]
assert "SERIAL-SECRET" not in repr(d)
assert d[1] == {"slot": "", "size": 0, "type": "", "speed": None, "configured": None, "maker": "", "part": ""}, d[1]
assert d[2]["size"] == 64 * 2**30 and d[2]["type"] == "DDR5" and d[2]["configured"] is None, d[2]
assert parse_dimms(b"") == [] and parse_dimms(b"\x11\x28") == []
hw = hardware()  # against this machine: must not raise
assert set(hw) == {"system", "cpu", "dimms", "disks"}, hw
print(hw["cpu"], hw["disks"][:2])
print("ok")
