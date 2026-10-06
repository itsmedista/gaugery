"""Firewall and Tailscale readers. Run: python test_netaccess.py (inside the gaugery image)."""
import json

from netaccess import clean_tailscale, parse_firewalld_zone, parse_ufw_rules

# ---- ufw: the formats ufw writes, IPv6 duplicates, apps, routes, interfaces, hex comments
ufw = """
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### limit tcp 2222 0.0.0.0/0 any 203.0.113.0/24 in comment=6f6c6420737368
### tuple ### deny any any 0.0.0.0/0 any 198.51.100.7 in_eth0
### tuple ### allow any 80,443 0.0.0.0/0 any 0.0.0.0/0 Nginx%20Full - in
### tuple ### route:allow_log tcp 8080 10.0.0.5 any 0.0.0.0/0 in
### tuple ### reject udp 53 0.0.0.0/0 any 0.0.0.0/0 out
### tuple ### allow tcp 22 ::/0 any ::/0 in
### tuple ### garbage line
-A ufw-user-input -p tcp --dport 22 -j ACCEPT
"""
r = parse_ufw_rules(ufw)
assert len(r) == 7, r
assert r[0] == {"action": "allow", "route": False, "direction": "in", "interface": "", "proto": "tcp", "to": "any",
                "port": "22", "app": "", "from": "any", "from_port": "", "from_app": "", "comment": ""}, r[0]
assert r[1]["action"] == "limit" and r[1]["from"] == "203.0.113.0/24" and r[1]["comment"] == "old ssh"
assert r[2]["action"] == "deny" and r[2]["interface"] == "eth0" and r[2]["port"] == ""
assert r[3]["app"] == "Nginx Full"
assert r[4]["route"] and r[4]["action"] == "allow" and r[4]["to"] == "10.0.0.5"
assert r[5]["direction"] == "out" and r[5]["action"] == "reject"
assert json.dumps(r[6], sort_keys=True) == json.dumps(r[0], sort_keys=True)  # v6 copy collapses to the same rule
assert parse_ufw_rules("") == [] and parse_ufw_rules(None) == []

# ---- firewalld zone
z = parse_firewalld_zone("""<?xml version="1.0"?><zone target="DROP"><short>Public</short>
  <service name="ssh"/><port protocol="tcp" port="8080"/><interface name="eth0"/><source address="10.0.0.0/8"/>
  <rule family="ipv4"><source address="192.0.2.9"/><service name="http"/><reject/></rule>
  <rule><source address="192.0.2.0/24" invert="true"/><port port="22" protocol="tcp"/><drop/></rule></zone>""", "public")
assert z["target"] == "drop" and z["interfaces"] == ["eth0"] and z["sources"] == ["10.0.0.0/8"]
assert [x["action"] for x in z["rows"]] == ["allow", "allow", "reject", "deny"], z["rows"]
assert z["rows"][2]["what"] == "ipv4 from 192.0.2.9 service http", z["rows"][2]
assert z["rows"][3]["what"] == "from not 192.0.2.0/24 port 22/tcp", z["rows"][3]

# ---- Tailscale: only the shown fields, no keys or account emails, funnel detected
raw = {"status": {
    "Version": "1.76.1-t1234", "BackendState": "Running",
    "CurrentTailnet": {"Name": "example.org", "MagicDNSEnabled": True},
    "Self": {"HostName": "web1", "DNSName": "web1.tail1.ts.net.", "TailscaleIPs": ["100.64.0.1", "fd7a::1"], "OS": "linux",
             "PublicKey": "nodekey:SECRETISH", "ExitNodeOption": True, "KeyExpiry": "2027-01-01T00:00:00Z"},
    "Peer": {"k1": {"HostName": "<img src=x onerror=alert(1)>", "TailscaleIPs": ["100.64.0.2"], "Online": False, "OS": "windows"},
             "k2": {"HostName": "exit", "TailscaleIPs": ["100.64.0.3"], "Online": True, "ExitNode": True, "Tags": ["tag:exit"]}},
    "User": {"1": {"LoginName": "owner@example.org"}}, "Health": ["Some health warning"]},
    "serve": {"TCP": {"443": {"HTTPS": True}, "22": {"TCPForward": "127.0.0.1:22"}, "80": {"HTTP": True}},
              "Web": {"web1.tail1.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:3000"}, "/files": {"Path": "/srv/pub"}}},
                      "web1.tail1.ts.net:80": {"Handlers": {"/": {"Text": "hi"}}}},
              "AllowFunnel": {"web1.tail1.ts.net:443": True},
              "Foreground": {"sess": {"Web": {"web1.tail1.ts.net:8443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9000"}}}}}}}}
c = clean_tailscale(raw)
dump = json.dumps(c)
assert "SECRETISH" not in dump and "owner@example.org" not in dump
assert c["state"] == "Running" and c["version"] == "1.76.1" and c["tailnet"] == "example.org" and c["magic_dns"]
assert c["self"]["dns"] == "web1.tail1.ts.net" and c["self"]["exit_option"]
assert c["exit_node"] == "exit" and c["peer_count"] == 2 and c["peers"][0]["name"] == "exit"   # online first
assert c["peers"][1]["name"] == "<img src=x onerror=alert(1)>"   # kept as text; the page escapes it
serve = {(x["port"], x["path"]): x for x in c["serve"]}
assert serve[("443", "/")]["public"] and serve[("443", "/")]["target"] == "http://127.0.0.1:3000"
assert serve[("443", "/files")]["target"] == "files: /srv/pub"
assert serve[("80", "/")]["kind"] == "http" and serve[("80", "/")]["target"] == "text" and not serve[("80", "/")]["public"]
assert serve[("22", "")]["kind"] == "tcp" and not serve[("22", "")]["public"]
assert serve[("8443", "/")]["target"] == "http://127.0.0.1:9000"
# hostile or broken input never raises, and sizes are capped
for bad in (None, [], "x", {"status": "nope"}, {"status": {"Peer": {"a": "b"}, "Self": [1]}, "serve": {"Web": {"h:1": {"Handlers": []}}}}):
    clean_tailscale(bad)
big = clean_tailscale({"status": {"Peer": {str(i): {"HostName": "x" * 5000} for i in range(500)}}, "serve": None})
assert len(big["peers"]) == 200 and big["peer_count"] == 500 and len(big["peers"][0]["name"]) == 80
assert big["serve_known"] is False
assert clean_tailscale({"error": "not installed"}) == {"error": "not installed"}
print("ok")
