import argparse
import json
import os
import sys

DEFAULT_CONFIG_DIR = "/var/mobile/Library/frida-config"

KNOWN_SERVICES = {
    "frida-server": {
        "package": "re.frida.server",
        "binary": "/usr/sbin/frida-server",
        "label": "re.frida.server",
        "plist": "/Library/LaunchDaemons/re.frida.server.plist",
        "args": DEFAULT_CONFIG_DIR + "/re.frida.server.args",
        "defaultPort": 27042,
        "protocol": "standard",
    },
    "frida-stealth": {
        "package": "re.frida.stealth",
        "binary": "/usr/sbin/frida-server-stealth",
        "label": "re.frida.stealth",
        "plist": "/Library/LaunchDaemons/re.frida.stealth.plist",
        "args": DEFAULT_CONFIG_DIR + "/re.frida.stealth.args",
        "defaultPort": 27043,
        "protocol": "frnda",
    },
}


def ssh_connect(host, port, user, password):
    try:
        import paramiko
    except ImportError:
        raise SystemExit(
            "frida-ctl needs paramiko to talk to the device: pip install paramiko"
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port, user, password, timeout=30)
    return client


def run(client, cmd, use_sudo=True, password=None):
    if use_sudo and password:
        remote_tmp = "/tmp/.frida-ctl-%d.sh" % abs(hash(cmd))
        cmd_b64 = __import__("base64").b64encode(cmd.encode("utf-8")).decode("ascii")
        wrapper = "printf '%%s' '%s' | base64 -d > %s; chmod 700 %s; echo %s | sudo -S bash %s; rm -f %s" % (
            cmd_b64, remote_tmp, remote_tmp, password, remote_tmp, remote_tmp
        )
        stdin, stdout, stderr = client.exec_command(wrapper)
    else:
        stdin, stdout, stderr = client.exec_command(cmd)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def shell_quote(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"


def read_args(client, service, password):
    spec = KNOWN_SERVICES[service]
    code, out, err = run(client, "cat %s 2>/dev/null || true" % spec["args"], True, password)
    lines = [l for l in out.splitlines() if l.strip() and not l.strip().startswith("#")]
    return lines


def write_args(client, service, args, password):
    spec = KNOWN_SERVICES[service]
    content = "# frida startup flags, one per line\n" + "\n".join(args) + "\n"
    cmd = (
        "mkdir -p %s && chmod 700 %s && cat > %s <<'ARGS'\n%sARGS\nchmod 600 %s"
        % (
            DEFAULT_CONFIG_DIR,
            DEFAULT_CONFIG_DIR,
            spec["args"],
            content,
            spec["args"],
        )
    )
    code, out, err = run(client, cmd, True, password)
    if code != 0:
        raise SystemExit("failed to write args: %s" % err)
    return content


def build_plist_cmd(service):
    spec = KNOWN_SERVICES[service]
    script = r"""
set -e
ARGS_FILE='@ARGS@'
PLIST='@PLIST@'
LABEL='@LABEL@'
SERVER='@BINARY@'

{
  echo '<?xml version="1.0" encoding="UTF-8"?>'
  echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
  echo '<plist version="1.0">'
  echo '<dict>'
  echo '	<key>Label</key>'
  echo "	<string>$LABEL</string>"
  echo '	<key>ProgramArguments</key>'
  echo '	<array>'
  echo "		<string>$SERVER</string>"
  while IFS= read -r line; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    esc=$(printf '%s' "$line" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g')
    echo "		<string>$esc</string>"
  done < "$ARGS_FILE"
  echo '	</array>'
  echo '	<key>UserName</key>'
  echo '	<string>root</string>'
  echo '	<key>POSIXSpawnType</key>'
  echo '	<string>Interactive</string>'
  echo '	<key>RunAtLoad</key>'
  echo '	<true/>'
  echo '	<key>KeepAlive</key>'
  echo '	<true/>'
  echo '	<key>ThrottleInterval</key>'
  echo '	<integer>5</integer>'
  echo '	<key>ExecuteAllowed</key>'
  echo '	<true/>'
  echo '</dict>'
  echo '</plist>'
} > "$PLIST"
chmod 644 "$PLIST"
"""
    return (
        script.replace("@ARGS@", spec["args"])
        .replace("@PLIST@", spec["plist"])
        .replace("@LABEL@", spec["label"])
        .replace("@BINARY@", spec["binary"])
    )


def reload_service(client, service, password):
    spec = KNOWN_SERVICES[service]
    script = build_plist_cmd(service) + """
launchctl unload %s >/dev/null 2>&1 || true
sleep 1
launchctl load %s
sleep 2
launchctl list | grep %s
""" % (spec["plist"], spec["plist"], spec["label"])
    return run(client, script, True, password)


def cmd_list(client, password):
    for name, spec in KNOWN_SERVICES.items():
        code, out, _ = run(
            client, "dpkg -l %s 2>/dev/null | tail -1" % spec["package"], True, password
        )
        installed = "ii" in out
        args = read_args(client, name, password) if installed else []
        print("%-14s %-10s port=%-6d protocol=%s"
              % (name, "installed" if installed else "absent",
                 spec["defaultPort"], spec["protocol"]))
        if installed:
            print("    args: %s" % (" ".join(args) if args else "(none)"))


def cmd_show(client, service, password):
    spec = KNOWN_SERVICES[service]
    args = read_args(client, service, password)
    print("service: %s" % service)
    print("package: %s" % spec["package"])
    print("binary : %s" % spec["binary"])
    print("plist  : %s" % spec["plist"])
    print("args   : %s" % (" ".join(args) if args else "(none)"))
    code, out, _ = run(client, "launchctl list | grep %s || true" % spec["label"], False)
    print("status : %s" % (out.strip() or "not running"))


def cmd_set(client, service, extra_args, password):
    if not extra_args:
        raise SystemExit("no flags given")
    write_args(client, service, extra_args, password)
    code, out, err = reload_service(client, service, password)
    print("written: %s" % " ".join(extra_args))
    print(out.strip() or err.strip())


def cmd_add(client, service, new_args, password):
    args = read_args(client, service, password) + new_args
    write_args(client, service, args, password)
    reload_service(client, service, password)
    print("args now: %s" % " ".join(args))


def cmd_ports(client, password):
    code, out, _ = run(client, "netstat -an | grep LISTEN", False)
    for line in out.splitlines():
        if ".2704" in line or ".6553" in line:
            print(line.strip())


def cmd_doctor(client, password):
    code, out, _ = run(client, "uname -a; dpkg --print-architecture", False)
    print(out.strip())
    print()
    cmd_list(client, password)
    print()
    print("listening frida ports:")
    cmd_ports(client, password)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="frida-ctl",
        description="Manage installed frida-server services and their startup flags on a jailbroken iOS device.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222, help="SSH port (iproxy)")
    parser.add_argument("--user", default="mobile")
    parser.add_argument("--password", default="123456")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show installed services and their flags")
    sub.add_parser("doctor", help="device summary, services and listening ports")
    sub.add_parser("ports", help="show frida listening ports")

    p_show = sub.add_parser("show", help="detail one service")
    p_show.add_argument("service", choices=sorted(KNOWN_SERVICES))

    p_set = sub.add_parser("set", help="replace the startup flags of a service")
    p_set.add_argument("service", choices=sorted(KNOWN_SERVICES))
    p_set.add_argument("flags", nargs=argparse.REMAINDER,
                       help="flags to pass to frida-server, e.g. --listen 0.0.0.0:65530 --token abc")

    p_add = sub.add_parser("add", help="append flags without replacing existing ones")
    p_add.add_argument("service", choices=sorted(KNOWN_SERVICES))
    p_add.add_argument("flags", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)

    if args.command in ("set", "add"):
        flags = [f for f in args.flags if f != "--"]
        if not flags:
            parser.error("%s requires at least one flag" % args.command)

    client = ssh_connect(args.host, args.port, args.user, args.password)
    try:
        if args.command == "list":
            cmd_list(client, args.password)
        elif args.command == "doctor":
            cmd_doctor(client, args.password)
        elif args.command == "ports":
            cmd_ports(client, args.password)
        elif args.command == "show":
            cmd_show(client, args.service, args.password)
        elif args.command == "set":
            cmd_set(client, args.service, flags, args.password)
        elif args.command == "add":
            cmd_add(client, args.service, flags, args.password)
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())