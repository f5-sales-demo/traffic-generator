"""Native DVWA API protocol content stays bound to its exact route and method."""

from traffic_native_identity import native_identity


def test_auth_bypass_native_json_and_empty_unauthenticated_read():
    path = "/dvwa/vulnerabilities/authbypass/get_user_data.php"
    assert native_identity(
        path,
        "GET",
        200,
        "application/json",
        '[{"user_id":"1","first_name":"admin","surname":"admin"}]',
    )
    assert native_identity(path, "GET", 200, "text/html", "")
    assert not native_identity(
        path, "GET", 200, "application/json", '[{"unrelated":1}]'
    )
    change = "/dvwa/vulnerabilities/authbypass/change_user_details.php"
    assert native_identity(change, "POST", 200, "application/json", '{"result":"ok"}')
    assert not native_identity(
        change, "GET", 200, "application/json", '{"result":"ok"}'
    )
    assert not native_identity(
        change, "POST", 200, "application/json", '{"result":"wrong"}'
    )
