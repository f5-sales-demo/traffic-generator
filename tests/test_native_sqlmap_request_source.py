"""Supervised SQLMap must consume preserved request files and drain native reports."""

from pathlib import Path


def test_all_five_sqlmap_scans_use_declared_targets_and_complete_reports():
    source = (
        Path(__file__).parents[1] / "suites/juice-shop-exploits/12-automated-sqlmap.sh"
    ).read_text()
    assert "--batch --ignore-stdin" in source
    assert source.count("${SQLMAP_CMD} ${SQLMAP_OPTS}") == 5
    assert source.count("--dbms=sqlite") == 5
    assert "| head -" not in source
    assert source.count("| sed -n") >= 5
    assert '-r "${TMPDIR}/login-request.txt"' in source
    assert '-r "${TMPDIR}/feedback-request.txt"' in source
    assert '-r "${TMPDIR}/register-request.txt"' in source
