"""Separate Set-Cookie fields retain exact native values without comma folding."""

from traffic_cookie_readback import native_session_cookie


def test_separate_cookie_fields_preserve_value_and_reject_ambiguity():
    assert (
        native_session_cookie(["dvwaSession=1", "ves_session=synthetic; Path=/"]) == "1"
    )
    assert native_session_cookie(["dvwaSession=2; Path=/", "other=value"]) == "2"
    assert native_session_cookie(["other=value"]) is None
    assert native_session_cookie(["dvwaSession=1", "dvwaSession=2"]) is None
    assert native_session_cookie(["dvwaSession=1,"]) is None
