import os
import shutil
import subprocess
import tempfile


class SigningError(RuntimeError):
    pass


def _run(args, env, input_bytes=None):
    proc = subprocess.run(
        args,
        env=env,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise SigningError(
            "%s failed (%d): %s"
            % (args[0], proc.returncode, proc.stderr.decode("utf-8", "replace").strip())
        )
    return proc.stdout


def find_gpg():
    for name in ("gpg", "gpg2"):
        path = shutil.which(name)
        if path:
            return path
    raise SigningError("gpg not found in PATH")


def gnupg_home_env(home):
    path = os.path.abspath(home)
    if os.name == "nt":
        drive, rest = os.path.splitdrive(path)
        if drive:
            return "/" + drive[0].lower() + rest.replace("\\", "/")
    return path


def sign_apt_release(apt_dir, dist, key_armored, passphrase=None):
    gpg = find_gpg()
    home = tempfile.mkdtemp(prefix="apt-gnupg-")
    env = dict(os.environ)
    env["GNUPGHOME"] = gnupg_home_env(home)
    env["LC_ALL"] = "C"
    try:
        os.chmod(home, 0o700)
        _run([gpg, "--batch", "--quiet", "--import"], env, key_armored.encode("utf-8"))

        fingerprint = _run(
            [gpg, "--batch", "--with-colons", "--list-secret-keys"], env
        ).decode("utf-8", "replace")
        keyid = None
        for line in fingerprint.splitlines():
            if line.startswith("fpr:"):
                keyid = line.split(":")[9]
                break
        if not keyid:
            raise SigningError("no secret key found after import")

        sign_args = [
            gpg,
            "--batch",
            "--yes",
            "--armor",
            "--local-user",
            keyid,
            "--digest-algo",
            "SHA512",
        ]
        if passphrase:
            sign_args += ["--pinentry-mode", "loopback", "--passphrase", passphrase]

        base = apt_dir
        release_path = os.path.join(base, "Release")
        release_bytes = open(release_path, "rb").read()

        clear = _run(sign_args + ["--clearsign"], env, release_bytes)
        with open(os.path.join(base, "InRelease"), "wb") as f:
            f.write(clear)

        detached = _run(sign_args + ["--detach-sign"], env, release_bytes)
        with open(os.path.join(base, "Release.gpg"), "wb") as f:
            f.write(detached)

        public = _run([gpg, "--batch", "--armor", "--export", keyid], env)
        with open(os.path.join(apt_dir, "public.gpg"), "wb") as f:
            f.write(public)

        return {
            "keyid": keyid,
            "inRelease": os.path.join(base, "InRelease"),
            "releaseGpg": os.path.join(base, "Release.gpg"),
            "publicKey": os.path.join(apt_dir, "public.gpg"),
        }
    finally:
        shutil.rmtree(home, ignore_errors=True)


def verify_apt_release(apt_dir, dist):
    gpg = find_gpg()
    home = tempfile.mkdtemp(prefix="apt-verify-")
    env = dict(os.environ)
    env["GNUPGHOME"] = gnupg_home_env(home)
    env["LC_ALL"] = "C"
    try:
        os.chmod(home, 0o700)
        public = os.path.join(apt_dir, "public.gpg")
        _run([gpg, "--batch", "--quiet", "--import", public], env)
        base = apt_dir
        _run([gpg, "--batch", "--verify", os.path.join(base, "InRelease")], env)
        _run(
            [gpg, "--batch", "--verify", os.path.join(base, "Release.gpg"), os.path.join(base, "Release")],
            env,
        )
        return True
    finally:
        shutil.rmtree(home, ignore_errors=True)