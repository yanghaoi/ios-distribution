import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
)

import deb_builder

TOKENS = (b"frida-1.0", b"/usr/lib/frida", b"frida-agent.dylib", b"re.frida.", b"re.frnda.")


def scan(path):
    members = deb_builder.read_ar(open(path, "rb").read())
    _name, data = deb_builder.read_data(members)
    print("===", os.path.basename(path))
    for member, body in deb_builder.iter_tar(data):
        if body is None:
            continue
        if not ("frida-server" in member.name or "frida-agent" in member.name):
            continue
        print("  ", member.name, len(body))
        for token in TOKENS:
            n = body.count(token)
            if n:
                print("      %-20s %d" % (token.decode(), n))
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: check_agent_layout.py <deb> [deb...]")
        raise SystemExit(2)
    for arg in sys.argv[1:]:
        scan(arg)