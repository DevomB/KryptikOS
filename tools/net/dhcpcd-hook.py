#!/usr/bin/python3 -I
"""dhcpcd's hook in the net zone: the uplinks' name servers into the zone's resolv.conf.

dhcpcd's privileged helper runs it as root with the environment the unprivileged
side sends, so nothing in that environment is trusted: each value is checked for
form, the state names only an interface and a protocol that pass, and the one
file written holds nothing but nameserver lines. Paths come from the command
line, which dhcpcd never fills, so the tests can move them and a lease cannot.

    dhcpcd-hook [--state DIR] [--out FILE]
"""
import ipaddress
import os
import re
import sys
import tempfile

STATE = "/run/lease-dns"
OUT = "/tmp/resolv.conf"
IFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")
PROTOCOLS = ("dhcp", "dhcp6", "ra", "ipv4ll", "link", "static", "static6")
PER_SOURCE = 8
IN_ALL = 16


def address(token, iface):
    """An IP literal, or None; a scope may only name the interface itself."""
    text, _, scope = token.partition("%")
    if scope and scope != iface:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.is_unspecified or addr.is_multicast:
        return None
    return str(addr) + ("%" + scope if scope else "")


def servers(env, iface):
    """The servers this event names, in order, each checked."""
    found = []
    words = env.get("new_domain_name_servers", "").split() + env.get("new_dhcp6_name_servers", "").split()
    # Router advertisements: nd<i>_rdnss<j>_servers, kept while their lifetime runs.
    for i in range(1, 9):
        for j in range(1, 9):
            listed = env.get("nd%d_rdnss%d_servers" % (i, j))
            if listed is None:
                continue
            life = env.get("nd%d_rdnss%d_lifetime" % (i, j), "0")
            # ASCII digits only: isdigit() also takes "²", which int() refuses.
            if re.fullmatch(r"[0-9]{1,10}", life) and int(life) > 0:
                words += listed.split()
    for w in words[:4 * PER_SOURCE]:
        a = address(w, iface)
        if a is not None and a not in found:
            found.append(a)
    return found[:PER_SOURCE]


def write_state(state, key, addrs):
    os.makedirs(state, mode=0o700, exist_ok=True)
    path = os.path.join(state, key)
    if not addrs:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return
    fd, tmp = tempfile.mkstemp(dir=state, prefix=".new.")
    with os.fdopen(fd, "w") as f:
        f.write("".join(a + "\n" for a in addrs))
    os.replace(tmp, path)


def rebuild(state, out):
    """resolv.conf from every source's file, each line checked again."""
    names = []
    try:
        keys = sorted(os.listdir(state))
    except FileNotFoundError:
        keys = []
    for key in keys:
        iface, _, proto = key.rpartition(".")
        if not IFACE.match(iface) or proto not in PROTOCOLS:
            continue
        try:
            fd = os.open(os.path.join(state, key), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            continue
        with os.fdopen(fd) as f:
            lines = f.read(4096).split("\n")
        for line in lines[:PER_SOURCE]:
            a = address(line.strip(), iface)
            if a is not None and a not in names:
                names.append(a)
    names = names[:IN_ALL]
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(out), prefix=".resolv.")
    with os.fdopen(fd, "w") as f:
        f.write("".join("nameserver %s\n" % a for a in names))
    os.chmod(tmp, 0o644)
    os.replace(tmp, out)


def main(argv, env):
    state, out = STATE, OUT
    args = argv[1:]
    while args:
        if args[0] == "--state" and len(args) > 1:
            state = args[1]
        elif args[0] == "--out" and len(args) > 1:
            out = args[1]
        else:
            print("usage: dhcpcd-hook [--state DIR] [--out FILE]", file=sys.stderr)
            return 2
        args = args[2:]
    iface = env.get("interface", "")
    proto = env.get("protocol", "")
    reason = env.get("reason", "")
    if not IFACE.match(iface) or proto not in PROTOCOLS:
        return 0
    key = "%s.%s" % (iface, proto)
    if env.get("if_up") == "true" or reason == "ROUTERADVERT":
        write_state(state, key, servers(env, iface))
    elif env.get("if_down") == "true":
        write_state(state, key, [])
    else:
        return 0
    rebuild(state, out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv, dict(os.environ)))
