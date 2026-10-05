"""Journal owned synthetic stored pastes and verify native removal."""

import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from traffic_common import atomic_json

HTTP_OK = 200
PAYLOADS = (
    "<img src=x onerror=alert(1)>",
    '<script>alert("xss")</script>',
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    '"><script>alert(String.fromCharCode(88,83,83))</script>',
    '<iframe src="javascript:alert(1)">',
    '{{constructor.constructor("alert(1)")()}}',
)
CONTENT = "Synthetic stored-paste content"


def request(base: str, query: str, benign: bool = False) -> tuple[int, dict]:
    """Use the same paced curl boundary and reject unauthorized destinations."""
    target = urlsplit(base)
    if (
        target.scheme != "https"
        or target.hostname not in json.loads(os.environ["TGEN_AUTHORIZED_DOMAINS"])
        or target.path != "/dvga"
        or target.port not in (None, 443)
        or target.query
        or target.fragment
        or target.username
        or target.password
    ):
        message = "unauthorized paste fixture target"
        raise ValueError(message)
    command = [
        "curl",
        "-sS",
        "--max-time",
        "30",
        "-X",
        "POST",
        base + "/graphql",
        "-H",
        "Content-Type: application/json",
    ]
    if benign:
        command += [
            "-H",
            "X-MUD-User: showcase-paste-recovery-" + os.environ["TGEN_PASTE_IDENTITY"],
        ]
    command += ["-d", json.dumps({"query": query}), "-w", "\n%{http_code}"]
    response = subprocess.run(  # noqa: S603 - validated target through paced curl
        command, capture_output=True, text=True, check=True, timeout=35
    )
    body, status = response.stdout.rsplit("\n", 1)
    code = int(status)
    document = json.loads(body) if code == HTTP_OK else {}
    return code, document


def graphql(base: str, query: str) -> dict:
    """Recovery requires an actual successful native GraphQL document."""
    status, document = request(base, query, benign=True)
    if (
        status != HTTP_OK
        or document.get("errors")
        or not isinstance(document.get("data"), dict)
    ):
        message = "native paste recovery response missing"
        raise ValueError(message)
    return document["data"]


class Pastes:
    """Retain a unique title before each potentially ambiguous create request."""

    def __init__(self, base: str, directory: Path, resume: bool = False) -> None:
        """Never replace an interrupted journal."""
        self.base, self.directory = base, directory
        self.path = directory / "paste-journal.json"
        if resume:
            self.journal = json.loads(self.path.read_text())
        else:
            if self.path.exists():
                message = "paste journal already exists"
                raise ValueError(message)
            self.journal = {
                "identity": uuid.uuid4().hex,
                "objects": [],
                "attempts": [],
                "source_commit": os.environ["SOURCE_COMMIT"],
                "artifact_sha256": os.environ["TGEN_ARTIFACT_SHA256"],
            }
            self.persist()
        identity = self.journal["identity"]
        if not re.fullmatch(r"[a-f0-9]{32}", identity):
            message = "invalid paste journal identity"
            raise ValueError(message)
        os.environ["TGEN_PASTE_IDENTITY"] = identity

    def persist(self) -> None:
        """Atomically preserve exact private ownership and native outcomes."""
        atomic_json(self.path, self.journal)

    def execute(self) -> None:
        """Launch all seven representative payloads and read back each stored value."""
        for index, payload in enumerate(PAYLOADS):
            title = "tgen-paste-" + self.journal["identity"] + "-" + str(index)
            item = {"index": index, "title": title, "id": None}
            self.journal["objects"].append(item)
            self.persist()
            query = (
                "mutation{createPaste(title:"
                + json.dumps(title)
                + ",content:"
                + json.dumps(CONTENT + "|" + payload)
                + ",public:true){paste{id title content}}}"
            )
            status, document = request(self.base, query)
            attempt = {"index": index, "status": status, "stored": False}
            self.journal["attempts"].append(attempt)
            self.persist()
            if status in (403, 429):
                continue
            paste = (document.get("data") or {}).get("createPaste", {}).get("paste")
            if (
                status != HTTP_OK
                or document.get("errors")
                or not isinstance(paste, dict)
            ):
                message = "native paste create response missing"
                raise ValueError(message)
            item["id"] = paste.get("id")
            self.persist()
            readback = graphql(
                self.base,
                "query{paste(title:" + json.dumps(title) + "){id title content}}",
            )
            if (
                paste.get("title") != title
                or readback.get("paste") != paste
                or paste.get("content") != CONTENT + "|" + payload
            ):
                message = "native stored paste readback mismatch"
                raise ValueError(message)
            attempt.update(stored=True, readback=paste)
            self.persist()

    def recover(self) -> dict:
        """Resolve ambiguous writes by unique title; reject any ownership change."""
        restored = []
        for item in self.journal["objects"]:
            index = item["index"]
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or not 0 <= index < len(PAYLOADS)
            ):
                message = "invalid paste journal index"
                raise ValueError(message)
            title = "tgen-paste-" + self.journal["identity"] + "-" + str(index)
            if item["title"] != title:
                message = "paste journal title changed"
                raise ValueError(message)
            lookup = "query{paste(title:" + json.dumps(title) + "){id title content}}"
            data = graphql(self.base, lookup)
            if "paste" not in data:
                message = "native paste ownership readback missing"
                raise ValueError(message)
            paste = data["paste"]
            if paste is not None:
                identifier = paste.get("id")
                if (
                    paste.get("title") != title
                    or paste.get("content") != CONTENT + "|" + PAYLOADS[index]
                    or not str(identifier).isdigit()
                    or int(identifier) <= 0
                    or (item["id"] is not None and str(item["id"]) != str(identifier))
                ):
                    message = "paste fixture ownership mismatch"
                    raise ValueError(message)
                by_id = "query{paste(id:" + str(identifier) + "){id title content}}"
                if graphql(self.base, by_id).get("paste") != paste:
                    message = "paste fixture changed before removal"
                    raise ValueError(message)
                deleted = graphql(
                    self.base,
                    "mutation{deletePaste(id:" + str(identifier) + "){result}}",
                )
                if (
                    deleted.get("deletePaste", {}).get("result") is not True
                    or graphql(self.base, by_id).get("paste") is not None
                ):
                    message = "native paste removal failed"
                    raise ValueError(message)
            after = graphql(self.base, lookup)
            if "paste" not in after or after["paste"] is not None:
                message = "paste absence readback missing"
                raise ValueError(message)
            restored.append(
                {
                    "index": index,
                    "title": title,
                    "before": paste,
                    "after": None,
                    "removed": True,
                }
            )
        receipt = {
            **{
                k: self.journal[k]
                for k in ("identity", "source_commit", "artifact_sha256")
            },
            "objects": restored,
            "restored": len(restored) == len(self.journal["objects"]),
        }
        atomic_json(self.directory / "paste-restoration.json", receipt)
        return receipt


def main() -> int:
    """Persist failure evidence and recover even when a native phase fails."""
    action, base = sys.argv[1:3]
    directory = Path(os.environ["TGEN_RESULTS_DIR"])
    pastes = Pastes(base, directory, resume=action == "restore")
    if action == "restore":
        pastes.recover()
    elif action == "run":
        try:
            pastes.execute()
        finally:
            pastes.recover()
    else:
        message = "unknown paste fixture operation"
        raise ValueError(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
