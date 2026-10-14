"""Install immutable upstream Hydra with native HTTP 401 form handling."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from urllib.request import urlopen

COMMIT = "6c11ce2dff19ce81630c12b001d821dcd4d1567c"
ARCHIVE_SHA256 = "16c4fe4771519dae3c00aada5f3b4ad192d0c82c95db8fb131bddb028b8875d6"

EXECUTABLE_MODE = 0o755


def verified_installation(destination: Path) -> bool:
    """Verify the declared source, installer and installed executable on readback."""
    try:
        receipt = json.loads((destination / "native-hydra-receipt.json").read_text())
        binary = destination / "bin/hydra"
        return (
            binary.is_file()
            and not binary.is_symlink()
            and binary.stat().st_mode & 0o777 == EXECUTABLE_MODE
            and receipt.get("source_commit") == COMMIT
            and receipt.get("archive_sha256") == ARCHIVE_SHA256
            and receipt.get("installer_sha256")
            == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            and receipt.get("binary_sha256")
            == hashlib.sha256(binary.read_bytes()).hexdigest()
        )
    except (OSError, ValueError):
        return False


def install(destination: Path) -> dict:
    """Verify upstream source and installer before promoting the native binary."""
    destination.mkdir(parents=True, exist_ok=True)
    installer_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    receipt_path = destination / "native-hydra-receipt.json"
    binary = destination / "bin/hydra"
    if verified_installation(destination):
        return json.loads(receipt_path.read_text())
    with tempfile.TemporaryDirectory(dir=destination) as temporary:
        root = Path(temporary)
        with urlopen(
            "https://codeload.github.com/vanhauser-thc/thc-hydra/tar.gz/" + COMMIT,
            timeout=60,
        ) as response:
            payload = response.read(20 * 1024**2 + 1)
        if (
            len(payload) > 20 * 1024**2
            or hashlib.sha256(payload).hexdigest() != ARCHIVE_SHA256
        ):
            message = "native Hydra archive digest mismatch"
            raise ValueError(message)
        archive = root / "hydra.tar.gz"
        archive.write_bytes(payload)
        with tarfile.open(archive) as source_archive:
            source_archive.extractall(root, filter="data")
        source = root / ("thc-hydra-" + COMMIT)
        with (root / "build.log").open("w") as log:
            subprocess.run(
                [
                    "/bin/sh",
                    "./configure",
                    "--disable-xhydra",
                    "--with-ssl=/usr",
                    "--with-ssl-lib=/usr/lib/x86_64-linux-gnu",
                ],
                cwd=source,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=120,
            )
            subprocess.run(
                ["/usr/bin/make", "-j2", "hydra"],
                cwd=source,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=300,
            )
        if not (source / "hydra").is_file():
            message = "native Hydra build produced no binary"
            raise ValueError(message)
        subprocess.run(  # noqa: S603 - fixed tool on a verified private build
            [
                "/usr/bin/strip",
                "--strip-all",
                "--remove-section=.note.gnu.build-id",
                "--remove-section=.comment",
                str(source / "hydra"),
            ],
            check=True,
            timeout=30,
        )
        binary.parent.mkdir(parents=True, exist_ok=True)
        staged = binary.with_name(".hydra-" + str(os.getpid()))
        shutil.copyfile(source / "hydra", staged)
        staged.chmod(EXECUTABLE_MODE)
        staged.replace(binary)
        receipt = {
            "source_commit": COMMIT,
            "archive_sha256": ARCHIVE_SHA256,
            "installer_sha256": installer_digest,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "version": "9.7",
            "behavior": "native form module option 1= completes each rejected HTTP 401 credential pair",
        }
        receipt_path.write_text(json.dumps(receipt))
        receipt_path.chmod(0o600)
        return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--destination", type=Path, default=Path("/opt/traffic-generator")
    )
    args = parser.parse_args()
    print(json.dumps(install(args.destination)))
