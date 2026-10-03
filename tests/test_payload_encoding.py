"""SQL quotes and shell metacharacters remain opaque encoder arguments."""

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]


def test_dvwa_sql_payload_encoder_round_trips_quotes():
    source = (ROOT / "suites/dvwa-exploits/06-sqli.sh").read_text()
    code = re.search(r"python3 -c '([^']+)'", source)[1]
    for payload in [
        "1' OR '1'='1",
        "1' UNION SELECT user,password FROM users-- -",
        "&&echo $(synthetic)",
    ]:
        result = subprocess.run(  # noqa: S603 - regression executes the fixed source encoder

            [sys.executable, "-c", code, payload], capture_output=True, text=True, check=True
        )
        assert unquote(result.stdout.strip()) == payload
