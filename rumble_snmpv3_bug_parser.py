#!/usr/bin/env python3
import json
import ipaddress

#
# This script parses a Rumble scan export for a SNMPv3 bug.
# The script is written in sections where an array or dict
# acts as the input, is filtered, and a new array or dict
# is produced. It's inefficient and takes up a ton of memory
# but I've been doing a lot of Power BI lately and I like
# how clear it is when manipulating data toward an end-state.
#


snmp_json_lines = []

with open("snmp.json") as f:
    for line in f:

        # When this JSON was created (assuming it's fixed now)
        # Rumble exports didn't wrap numeric values in quotes.
        # This causes Python's JSON module to throw an exception.

        try:
            rumble_json = json.loads(line)
        except json.decoder.JSONDecodeError:
            pass

        if "probe" in rumble_json and rumble_json["probe"] == "snmp":
            snmp_json_lines.append(rumble_json)




snmp_cisco_lines = []

for rumble_json in snmp_json_lines:
    info = rumble_json["info"]

    if "snmp.EngineID.Vendor" in info and info["snmp.EngineID.Vendor"] == "ciscoSystems":
        snmp_cisco_lines.append(rumble_json)




engine_ids = {}

for rumble_json in snmp_cisco_lines:

    ip = ipaddress.ip_address(rumble_json["host"])
    engine_id = rumble_json["info"]["snmp.EngineID.Raw"]

    if engine_id in engine_ids:
        engine_ids[engine_id].append(ip)
    else:
        engine_ids[engine_id] = [ip]




# Each engine_id is a unique router.
# Filter for engines with multiple IPs.

engines_multiple_ips = {}

for engine_id in engine_ids:
    router_ips = engine_ids[engine_id]

    if len(router_ips) > 1:
        engines_multiple_ips[engine_id] = router_ips




# Task: Remove ISP IPs if present.
# Assume /20 is the highest netblock. Group networks together by their common /20.
# Remove any slash20s with a single IP. Those are usually ISP IPs.

engines_multiple_ips_no_isp= {}
for engine_id in engines_multiple_ips:

    router_ips = engines_multiple_ips[engine_id]

    slash20s = {}

    # Convert each router IP into a CIDR with /20.
    # Group like IPs into a dict of /20s

    for router_ip in sorted(router_ips):

        cidr = "{}/20".format(router_ip)
        network = ipaddress.IPv4Interface(cidr).network

        # The dict key, based on /20 network, contains
        # an array of IP address objects that match.

        if network in slash20s:
            slash20s[network].append(router_ip)
        else:
            slash20s[network] = [router_ip]

    # Ignore any networks with only one IP.

    for network in slash20s:

        router_ips = slash20s[network]
        if len(router_ips) > 1:
            for ip in router_ips:
                if engine_id in engines_multiple_ips_no_isp:
                    engines_multiple_ips_no_isp[engine_id].append(ip)
                else:
                    engines_multiple_ips_no_isp[engine_id] = [ip]





winners = 0

size_to_cidr = {
    4096: 20,
    2048: 21,
    1024: 22,
    512: 23,
    256: 24,
    128: 25,
    64: 26,
    32: 27,
    16: 28,
    8: 29,
    4: 30,
}

for engine_id in engines_multiple_ips_no_isp:
    router_ips = engines_multiple_ips_no_isp[engine_id]
    count_network_ips = len(router_ips)

    low_ip = router_ips[0]
    low = int(low_ip)
    high_ip = router_ips[-1]
    high = int(high_ip)
    diff = high-low+1


    last_size = 8192
    for cidr_size in (4096, 2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4):
        if cidr_size/diff >= 1:
            last_size = cidr_size

    del router_ips[0]
    del router_ips[-1]
    remaining = len(router_ips)


    if diff == last_size:
        try:
            cidr = size_to_cidr[last_size]
            network_address = "{}/{}".format(low_ip, cidr)
            network = ipaddress.ip_network(network_address)

            print(network)
            print("Size is: ", last_size)
            print("IPs: {:d}".format(count_network_ips))
            print("Lowest IP: ", low_ip)
            print("Highest IP: ", high_ip)
            print("Remaining: ", remaining)
            print("")

            if remaining < 1:
                winners += 1
        except ValueError:
            pass
        
                

print("Count of SNMP JSON lines: ", len(snmp_json_lines))
print("Count of SNMP Cisco JSON lines: ", len(snmp_cisco_lines))
print("Count of unique engineIDs: ", len(engine_ids.keys()))

print("Candidates: ", len(engines_multiple_ips_no_isp.keys()))
print("Winners: ", winners)
