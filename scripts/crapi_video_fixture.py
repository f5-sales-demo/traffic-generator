"""Journal and restore a seeded user's exact video through authorized native APIs."""

import base64
import hashlib
import json
import os
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def request(
    base: str,
    path: str,
    token: str,
    body: bytes | None = None,
    method: str = "GET",
    content_type: str = "application/json",
) -> dict:
    """Fixture setup and recovery traverse the same authorized pacing boundary."""
    target = urlsplit(base)
    if (
        target.scheme != "https"
        or target.hostname not in json.loads(os.environ["TGEN_AUTHORIZED_DOMAINS"])
        or target.path != "/crapi"
        or target.port not in (None, 443)
    ):
        message = "unauthorized video fixture target"
        raise ValueError(message)
    req = Request(  # noqa: S310 - validated authorized HTTPS target
        base + path,
        data=body,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": content_type,
            "X-MUD-User": "waap-fixture-benign",
        },
    )
    with urlopen(req, timeout=60) as response:  # noqa: S310 - validated owned target
        return json.load(response)


def video_bytes(document: dict) -> bytes:
    """Reject missing/corrupt fixture media instead of silently dropping restoration."""
    encoded = document.get("profileVideo", "")
    if not isinstance(encoded, str) or not encoded.startswith(
        "data:image/jpeg;base64,"
    ):
        message = "native video fixture bytes missing"
        raise ValueError(message)
    return base64.b64decode(encoded.split(",", 1)[1], validate=True)


def recover(base: str, token: str, before: dict) -> dict:
    """Restore media, name and conversion parameters, then compare the native response."""
    identifier = before["id"]
    if not isinstance(identifier, int) or identifier <= 0:
        message = "invalid video fixture identity"
        raise ValueError(message)
    name = before.get("video_name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", name):
        message = "unsafe video fixture filename"
        raise ValueError(message)
    boundary = "tgen-" + uuid.uuid4().hex
    body = (
        (
            "--"
            + boundary
            + '\r\nContent-Disposition: form-data; name="file"; filename="'
            + name
            + '"\r\nContent-Type: video/mp4\r\n\r\n'
        ).encode()
        + video_bytes(before)
        + ("\r\n--" + boundary + "--\r\n").encode()
    )
    uploaded = request(
        base,
        "/identity/api/v2/user/videos",
        token,
        body,
        "POST",
        "multipart/form-data; boundary=" + boundary,
    )
    if uploaded.get("id") != identifier:
        message = "video fixture actor changed"
        raise ValueError(message)
    request(
        base,
        "/identity/api/v2/user/videos/" + str(identifier),
        token,
        json.dumps(
            {
                "id": identifier,
                "videoName": name,
                "conversion_params": before["conversion_params"],
            }
        ).encode(),
        "PUT",
    )
    after = request(base, "/identity/api/v2/user/videos/" + str(identifier), token)
    restored = all(
        after.get(key) == before.get(key)
        for key in ("id", "video_name", "conversion_params")
    ) and video_bytes(after) == video_bytes(before)

    def identity(document: dict) -> dict:
        return {
            "id": document.get("id"),
            "video_name": document.get("video_name"),
            "conversion_params": document.get("conversion_params"),
            "media_sha256": hashlib.sha256(video_bytes(document)).hexdigest(),
        }

    return {
        "before": identity(before),
        "after": identity(after),
        "source_commit": os.environ.get("SOURCE_COMMIT"),
        "artifact_sha256": os.environ.get("TGEN_ARTIFACT_SHA256"),
        "restored": restored,
        "video_id": identifier,
        "fields": ["video_name", "conversion_params", "profileVideo"],
    }


def main() -> int:
    """Snapshot before any upload and require restoration independently of attacks."""
    action, base = sys.argv[1:3]
    directory = Path(os.environ["TGEN_RESULTS_DIR"])
    journal = directory / "crapi-video-snapshot.json"
    token = os.environ["TGEN_VIDEO_TOKEN"]
    if action == "snapshot":
        identifier = int(os.environ["TGEN_CRAPI_VIDEO_ID"])
        document = request(
            base, "/identity/api/v2/user/videos/" + str(identifier), token
        )
        if document.get("id") != identifier or not video_bytes(document):
            message = "seeded video fixture unavailable"
            raise ValueError(message)
        journal.write_text(json.dumps(document))
        journal.chmod(0o600)
    elif action == "restore":
        receipt = recover(base, token, json.loads(journal.read_text()))
        path = directory / "video-restoration.json"
        path.write_text(json.dumps(receipt))
        path.chmod(0o600)
        if not receipt["restored"]:
            message = "native video restoration failed"
            raise ValueError(message)
    else:
        message = "unknown video fixture operation"
        raise ValueError(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
