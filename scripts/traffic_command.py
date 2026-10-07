"""Select the declared native scenario command without executing it."""

from pathlib import Path


def scenario_command(root: Path, scenario: dict, domain: str) -> list[str]:
    """Invoke native tools through explicit scoped adapters and shared pacing."""
    if scenario.get("adapter") == "native-order-mutation":
        return [
            "python3",
            str(root / "scripts/crapi_order_fixture.py"),
            "run",
            __import__("os").environ["TGEN_RESULTS_DIR"],
        ]
    adapters = {
        "dynamic-cache": "traffic_cache.py",
        "native-load": "native_load.py",
        "bounded-multiclient": "traffic_multiclient.py",
        "native-masscan": "native_masscan.py",
        "native-scanner": "native_scanners.py",
        "native-subfinder": "native_subfinder.py",
        "native-slow-headers": "native_slow_headers.py",
    }
    if scenario.get("adapter") in adapters:
        return [
            "python3",
            str(root / "scripts" / adapters[scenario["adapter"]]),
            scenario["id"],
            domain,
        ]
    if "report_contract" in scenario:
        return ["python3", str(root / "scripts/traffic_report.py"), scenario["id"]]
    if scenario["budget"] == "connection":
        return [
            "python3",
            str(root / "scripts/traffic_connections.py"),
            scenario["id"],
            domain,
        ]
    if scenario["kind"] == "csd-browser":
        return [
            "node",
            str(root / "suites/csd-violations/azure.mjs"),
            scenario["scenario"],
        ]
    return [
        "node" if scenario["kind"] == "javascript" else "bash",
        str(root / scenario["entrypoint"]),
        domain,
    ]
