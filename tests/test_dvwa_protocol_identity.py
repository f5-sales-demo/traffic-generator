"""Native DVWA API protocol content stays bound to its exact route and method."""

from traffic_native_identity import native_dvwa_redirect_identity, native_identity


def test_auth_bypass_native_json_and_empty_unauthenticated_read():
    path = "/dvwa/vulnerabilities/authbypass/get_user_data.php"
    assert native_identity(
        path,
        "GET",
        200,
        "application/json",
        '[{"user_id":"1","first_name":"Dana R.","surname":"Example"}]',
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


def test_native_dvwa_json_retains_php_text_html_media():
    path = "/dvwa/vulnerabilities/authbypass/get_user_data.php"
    body = '[{"user_id":"1","first_name":"Dana R.","surname":"Example"}]'
    assert native_identity(path, "GET", 200, "text/html; charset=UTF-8", body)
    denied = '{"result":"fail","error":"Access denied"}'
    assert native_identity(path, "GET", 200, "text/html", denied)
    assert not native_identity(path, "GET", 200, "text/html", '{"result":"other"}')
    change = "/dvwa/vulnerabilities/authbypass/change_user_details.php"
    assert native_identity(change, "POST", 200, "text/html", '{"result":"ok"}')
    assert not native_identity(change, "GET", 200, "text/html", '{"result":"ok"}')


def test_native_redirect_needs_exact_location_and_empty_native_body():
    path = "/dvwa/vulnerabilities/open_redirect/source/low.php?redirect=https%3A//evil.example.com"
    assert native_dvwa_redirect_identity(
        path, "GET", 302, b"", "https://evil.example.com"
    )
    assert not native_dvwa_redirect_identity(
        path, "GET", 302, b"", "https://other.example.com"
    )
    assert not native_dvwa_redirect_identity(
        path, "POST", 302, b"", "https://evil.example.com"
    )
    assert not native_dvwa_redirect_identity(
        path, "GET", 302, b"unrelated", "https://evil.example.com"
    )
    assert not native_dvwa_redirect_identity(
        path.replace("source/low.php", "other.php"),
        "GET",
        302,
        b"",
        "https://evil.example.com",
    )
