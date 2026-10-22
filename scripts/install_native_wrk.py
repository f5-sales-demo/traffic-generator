"""Install content-pinned native wrk with bounded request draining."""

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from urllib.request import urlopen

from wrk_drain_adapter import adapt, replace_once

COMMIT = "a211dd5a7050b1f9e8a9870b95513060e72ac4a0"
ARCHIVE_SHA256 = "172dd2788b22b210d37a68f11c91e82fdba6583d2a544f04b398a66507031229"

EXECUTABLE_MODE = 0o755

DEFAULT_TABLE = """local wrk = {
   scheme  = "http",
   host    = "localhost",
   port    = nil,
   method  = "GET",
   path    = "/",
   headers = {},
   body    = nil,
   thread  = nil,
}"""
DEFAULT_ASSIGNMENTS = """local wrk = {}
wrk.scheme = "http"
wrk.host = "localhost"
wrk.port = nil
wrk.method = "GET"
wrk.path = "/"
wrk.headers = {}
wrk.body = nil
wrk.thread = nil"""


def reproducible_source(source: Path) -> None:
    """Preserve native defaults without randomized serialized template tables."""
    lua = source / "src/wrk.lua"
    lua.write_text(replace_once(lua.read_text(), DEFAULT_TABLE, DEFAULT_ASSIGNMENTS))
    makefile = source / "Makefile"
    recipe = makefile.read_text()
    recipe = replace_once(
        recipe,
        "PREFIX=$(abspath $(ODIR)) BUILDMODE=static install",
        'PREFIX=/usr/local INSTALL_BIN="$(abspath $(ODIR))/bin" '
        'INSTALL_LIB="$(abspath $(ODIR))/lib" '
        'INSTALL_SHARE="$(abspath $(ODIR))/share" '
        'INSTALL_INC="$(abspath $(ODIR))/include/luajit-2.1" '
        "BUILDMODE=static install",
    )
    recipe = replace_once(
        recipe,
        'PATH="obj/bin:$(PATH)" luajit -b',
        'LUA_PATH="$(CURDIR)/obj/share/luajit-2.1.0-beta3/?.lua;;" '
        'PATH="obj/bin:$(PATH)" luajit -b',
    )
    makefile.write_text(recipe)


def verified_installation(destination: Path) -> bool:
    """Reject undeclared source, installer, adapter, binary or executable mode drift."""
    try:
        receipt = json.loads((destination / "native-wrk-receipt.json").read_text())
        binary = destination / "bin/wrk"
        return (
            binary.is_file()
            and not binary.is_symlink()
            and binary.stat().st_mode & 0o777 == EXECUTABLE_MODE
            and receipt.get("source_commit") == COMMIT
            and receipt.get("archive_sha256") == ARCHIVE_SHA256
            and receipt.get("installer_sha256")
            == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            and receipt.get("adapter_sha256")
            == hashlib.sha256(
                Path(__file__).with_name("wrk_drain_adapter.py").read_bytes()
            ).hexdigest()
            and receipt.get("binary_sha256")
            == hashlib.sha256(binary.read_bytes()).hexdigest()
        )
    except (OSError, ValueError):
        return False


def install(destination: Path) -> dict:
    """Verify upstream source and adapter before building/promoting the native binary."""
    destination.mkdir(parents=True, exist_ok=True)
    installer_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    adapter_digest = hashlib.sha256(
        Path(__file__).with_name("wrk_drain_adapter.py").read_bytes()
    ).hexdigest()
    receipt_path = destination / "native-wrk-receipt.json"
    binary = destination / "bin/wrk"
    if verified_installation(destination):
        return json.loads(receipt_path.read_text())
    with tempfile.TemporaryDirectory(dir=destination) as temporary:
        root = Path(temporary)
        with urlopen(
            "https://codeload.github.com/wg/wrk/tar.gz/" + COMMIT, timeout=60
        ) as response:
            payload = response.read(20 * 1024**2 + 1)
        if (
            len(payload) > 20 * 1024**2
            or hashlib.sha256(payload).hexdigest() != ARCHIVE_SHA256
        ):
            message = "native wrk archive digest mismatch"
            raise ValueError(message)
        archive = root / "wrk.tar.gz"
        archive.write_bytes(payload)
        with tarfile.open(archive) as source_archive:
            source_archive.extractall(root, filter="data")
        source = root / ("wrk-" + COMMIT)
        adapt(source)
        reproducible_source(source)
        with (root / "build.log").open("w") as log:
            subprocess.run(
                ["/usr/bin/make", "-j2", "WITH_OPENSSL=/usr", "VER=4.2.0-demo-drain"],
                cwd=source,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=300,
            )
        if not (source / "wrk").is_file():
            message = "native wrk build produced no binary"
            raise ValueError(message)
        subprocess.run(  # noqa: S603 - fixed tool on a verified private build
            [
                "/usr/bin/strip",
                "--strip-all",
                "--remove-section=.note.gnu.build-id",
                "--remove-section=.comment",
                str(source / "wrk"),
            ],
            check=True,
            timeout=30,
        )
        binary.parent.mkdir(parents=True, exist_ok=True)
        staged = binary.with_name(".wrk-" + str(os.getpid()))
        shutil.copyfile(source / "wrk", staged)
        staged.chmod(EXECUTABLE_MODE)
        staged.replace(binary)
        receipt = {
            "source_commit": COMMIT,
            "archive_sha256": ARCHIVE_SHA256,
            "adapter_sha256": adapter_digest,
            "installer_sha256": installer_digest,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "behavior": "stop new launches after duration and drain pending responses within native timeout",
        }
        receipt_path.write_text(json.dumps(receipt))
        receipt_path.chmod(0o600)
        return receipt


if __name__ == "__main__":
    print(json.dumps(install(Path("/opt/traffic-generator"))))
