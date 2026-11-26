"""The access rungs: session, role, device posture, egress and content.

Each rung is tested twice where a sibling exists: once against a three-line fake,
which pins the contract the rung actually relies on, and once against the real
sibling package, which proves that contract is the one the sibling ships.
"""
from __future__ import annotations

import importlib.util
from types import SimpleNamespace

import pytest
from awnboard import (
    ContentClean,
    DevicePosture,
    EgressAllowed,
    Gate,
    LiveSession,
    RoleGranted,
)

NOW = 1_700_000_000.0


def _has(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


# ── LiveSession ─────────────────────────────────────────────────────────────


class _Sessions:
    def __init__(self, live: dict):
        self.live = live

    def resolve(self, token):
        if token in self.live:
            return SimpleNamespace(ok=True, subject_id=self.live[token], reason="")
        return SimpleNamespace(ok=False, subject_id=None, reason="session revoked")


def test_live_session_admits_a_live_session_and_names_its_subject():
    c = LiveSession(_Sessions({"tok": "sam"})).check({"session": "tok"})
    assert c.met and c.detail == {"subject": "sam"}


def test_live_session_refuses_missing_revoked_and_someone_elses():
    rung = LiveSession(_Sessions({"tok": "sam"}))
    assert not rung.check({}).met
    revoked = rung.check({"session": "gone"})
    assert not revoked.met and revoked.why == "session revoked"
    other = rung.check({"session": "tok", "subject": "alex"})
    assert not other.met and "different subject" in other.why


def test_live_session_refuses_an_ok_that_names_nobody():
    class _Blank:
        def resolve(self, token):
            return SimpleNamespace(ok=True, subject_id="", reason="")

    assert not LiveSession(_Blank()).check({"session": "tok"}).met


def test_live_session_store_that_raises_is_unmet_not_a_500():
    class _Broken:
        def resolve(self, token):
            raise OSError("directory unreadable")

    a = Gate("app", requirements=[LiveSession(_Broken())]).admit({"session": "tok"})
    assert not a.admitted and "requirement raised" in a.failed[0].why


@pytest.mark.skipif(not _has("awiam"), reason="awiam is not installed")
def test_live_session_with_real_awiam_stops_working_on_deactivate(tmp_path):
    from awiam import Directory, Sessions, Subject

    directory = Directory(tmp_path / "dir.json")
    directory.put(Subject(id="sam"))
    sessions = Sessions(directory)
    token = sessions.issue("sam")
    rung = LiveSession(sessions)
    assert rung.check({"session": token, "subject": "sam"}).met
    directory.deactivate("sam")
    assert not rung.check({"session": token, "subject": "sam"}).met


# ── RoleGranted ─────────────────────────────────────────────────────────────


class _Policy:
    def __init__(self, grants: dict):
        self.grants = grants

    def check(self, subject, permission):
        if permission in self.grants.get(subject, ()):
            return SimpleNamespace(allowed=True, reason="granted", via=permission)
        return SimpleNamespace(allowed=False, reason=f"{subject} lacks {permission}", via=None)


def test_role_granted_admits_and_records_what_granted_it():
    c = RoleGranted(_Policy({"sam": ["app:wiki:read"]}), "app:wiki:read").check(
        {"subject": "sam"})
    assert c.met and c.detail["via"] == "app:wiki:read"


def test_role_granted_refusal_explains_to_the_operator_not_the_visitor():
    c = RoleGranted(_Policy({}), "app:wiki:read").check({"subject": "sam"})
    assert not c.met
    assert "app:wiki:read" in c.why          # the operator sees the missing grant
    assert "app:wiki:read" not in c.remedy   # the visitor is not handed the map


def test_role_granted_reads_the_resolved_subject_never_the_claim():
    rung = RoleGranted(_Policy({"sam": ["p"]}), "p")
    assert not rung.check({"as": "sam"}).met


def test_role_granted_needs_a_real_yes_not_a_truthy_answer():
    class _Loose:
        def check(self, subject, permission):
            return ("denied", "but truthy")

    assert not RoleGranted(_Loose(), "p").check({"subject": "sam"}).met


def test_role_granted_refuses_to_guard_nothing():
    with pytest.raises(ValueError):
        RoleGranted(_Policy({}), "")


@pytest.mark.skipif(not _has("awbac"), reason="awbac is not installed")
def test_role_granted_with_real_awbac():
    from awbac import Policy

    policy = Policy().role("staff", ["app:wiki:read"]).assign("sam", "staff")
    assert RoleGranted(policy, "app:wiki:read").check({"subject": "sam"}).met
    assert not RoleGranted(policy, "app:payroll:read").check({"subject": "sam"}).met
    assert not RoleGranted(policy, "app:wiki:read").check({"subject": "alex"}).met


# ── DevicePosture ───────────────────────────────────────────────────────────

FIT = {"device_id": "d1", "disk_encrypted": True, "screen_lock": True,
       "os_version": "16", "patch_level": "2026-09-05", "reported_at": NOW - 60}


def _posture(**kw):
    kw.setdefault("clock", lambda: NOW)
    return DevicePosture(**kw)


def test_posture_admits_a_fit_device():
    rung = _posture(require={"disk_encrypted": True, "screen_lock": True},
                    at_least={"os_version": "14", "patch_level": "2026-09-01"},
                    max_age_s=3600)
    c = rung.check({"device": FIT})
    assert c.met and c.detail == {"device_id": "d1"}


def test_posture_unreported_is_unmet_not_assumed():
    rung = _posture(require={"disk_encrypted": True})
    device = {k: v for k, v in FIT.items() if k != "disk_encrypted"}
    c = rung.check({"device": device})
    assert not c.met and "disk_encrypted: not reported" in c.why


def test_posture_names_every_failure_at_once():
    rung = _posture(require={"disk_encrypted": True},
                    at_least={"patch_level": "2026-10-01"}, max_age_s=30)
    c = rung.check({"device": dict(FIT, disk_encrypted=False)})
    assert not c.met
    assert c.detail["failed"] == ["disk_encrypted", "patch_level", "reported_at"]


def test_posture_a_truthy_string_is_not_true():
    rung = _posture(require={"disk_encrypted": True})
    assert not rung.check({"device": dict(FIT, disk_encrypted="yes")}).met


@pytest.mark.parametrize("have,floor,ok", [
    ("14", "14.0", True),        # unpadded, (14,) would sort below (14, 0)
    ("14.0.1", "14", True),
    ("13.9", "14", False),
    ("2026-09-05", "2026-09-01", True),
    ("2026-08-31", "2026-09-01", False),
    ("v14.1", "14", True),
    # free text is not a version: digits picked out of it are as likely a model
    # number as an OS release, so it reads as not reported
    ("Android 16", "14", False),
    ("Phone15,2 OS 12", "14", False),
    ("", "14", False),
])
def test_posture_version_floors(have, floor, ok):
    rung = _posture(at_least={"os_version": floor})
    assert rung.check({"device": dict(FIT, os_version=have)}).met is ok


@pytest.mark.parametrize("reported_at", [
    NOW - 7200, NOW + 86400, "soon", None,
    float("nan"), "nan", float("inf"), float("-inf"),   # NaN compares False to everything
])
def test_posture_stale_future_and_non_finite_reports_are_unmet(reported_at):
    rung = _posture(max_age_s=3600)
    assert not rung.check({"device": dict(FIT, reported_at=reported_at)}).met


def test_posture_needs_a_device_and_something_to_require():
    assert not _posture(require={"managed": True}).check({}).met
    assert not _posture(require={"managed": True}).check({"device": "d1"}).met
    with pytest.raises(ValueError):
        DevicePosture()
    with pytest.raises(ValueError):
        DevicePosture(at_least={"os_version": "latest"})


# ── EgressAllowed ───────────────────────────────────────────────────────────


class _Wall:
    def __init__(self, hosts):
        self.hosts = set(hosts)

    def check(self, host):
        return (True, SimpleNamespace(pattern=host)) if host in self.hosts else (False, None)


def test_egress_admits_a_listed_host_with_or_without_a_port():
    rung = EgressAllowed(_Wall({"api.example.com"}))
    assert rung.check({"destination": "api.example.com"}).met
    c = rung.check({"destination": "API.example.com:443"})
    assert c.met and c.detail["destination"] == "api.example.com"


@pytest.mark.parametrize("dest", [
    "", None, 443, "evil.example", "api.example.com@evil.example",
    "https://api.example.com", "api.example.com/path", "api.example.com?x=1",
    "api.example.com evil.example", " api.example.com", "api.example.com.",
    # what a separator blacklist misses
    "evil.example／.api.example.com",       # full-width slash, NFKC-folds to "/"
    "evil.example%2f.api.example.com", "evil.example;.api.example.com",
    "evil.example\n.api.example.com", "evil.example\x00.api.example.com",
    "evil.example:80.api.example.com", "api.example.com:port", "api.example.com:999999",
    "-api.example.com", "api..example.com", "a" * 64 + ".example.com",
])
def test_egress_refuses_anything_that_is_not_a_listed_bare_host(dest):
    wall = _DomainWall("api.example.com")
    assert not EgressAllowed(wall).check({"destination": dest}).met


class _DomainWall:
    """The permissive shape: a domain rule, which is what a suffix trick targets."""

    def __init__(self, domain):
        self.domain = domain

    def check(self, host):
        ok = host == self.domain or host.endswith("." + self.domain)
        return (True, SimpleNamespace(pattern=self.domain)) if ok else (False, None)


def test_egress_ipv6_needs_brackets_so_a_port_cannot_be_read_as_address():
    rung = EgressAllowed(_Wall({"fd00::1"}))
    assert rung.check({"destination": "[fd00::1]"}).met
    assert rung.check({"destination": "[FD00::1]:443"}).met
    assert not rung.check({"destination": "fd00::1"}).met      # bare: ambiguous
    assert not rung.check({"destination": "fd00::1:5"}).met    # was read as fd00::1 port 5


def test_egress_needs_a_real_yes():
    class _Loose:
        def check(self, host):
            return "allowed"

    assert not EgressAllowed(_Loose()).check({"destination": "api.example.com"}).met


@pytest.mark.skipif(not _has("awwall"), reason="awwall is not installed")
def test_egress_with_real_awwall():
    from awwall import Policy

    wall = Policy.from_dict({"rules": [
        {"pattern": "api.example.com", "rule_type": "exact"},
        {"pattern": "internal.example", "rule_type": "domain"},
    ]})
    rung = EgressAllowed(wall)
    assert rung.check({"destination": "api.example.com:443"}).met
    c = rung.check({"destination": "wiki.internal.example"})
    assert c.met and c.detail["rule"] == "internal.example"
    assert not rung.check({"destination": "evil.example"}).met
    assert not rung.check({"destination": "internal.example.evil.example"}).met


# ── ContentClean ────────────────────────────────────────────────────────────


def _inspector(seen: list):
    def inspect(data: bytes):
        seen.append(data)
        if b"SECRET" in data:
            return {"allowed": False, "findings": ["api_key"]}
        return {"allowed": True}
    return inspect


def test_content_clean_passes_clean_and_empty_content():
    seen: list = []
    rung = ContentClean(_inspector(seen))
    assert rung.check({"content": b"hello"}).met
    assert rung.check({"content": "hello"}).met
    assert rung.check({}).met and rung.check({"content": b""}).met
    assert seen == [b"hello", b"hello"]      # nothing to send is never inspected


def test_content_clean_blocks_and_keeps_names_never_the_matched_text():
    c = ContentClean(_inspector([])).check({"content": b"key=SECRET-abc123"})
    assert not c.met and c.detail["findings"] == ["api_key"]
    assert "SECRET" not in c.why and "abc123" not in c.why
    assert "SECRET" not in str(c.detail)


def test_content_clean_refuses_oversize_instead_of_sampling_it():
    seen: list = []
    rung = ContentClean(_inspector(seen), max_bytes=8)
    c = rung.check({"content": b"clean...SECRET"})
    assert not c.met and "at most 8" in c.why
    assert seen == []                         # the inspector never saw a prefix


@pytest.mark.parametrize("verdict", [None, "ok", {"allowed": "yes"}, {}, {"allowed": 1}])
def test_content_clean_needs_a_real_yes(verdict):
    assert not ContentClean(lambda data: verdict).check({"content": b"x"}).met


def test_content_clean_inspector_that_raises_is_unmet_not_admitted():
    def boom(data):
        raise TimeoutError("inspector unreachable")

    a = Gate("app", requirements=[ContentClean(boom)]).admit({"content": b"x"})
    assert not a.admitted


def test_content_clean_refuses_what_it_cannot_read():
    assert not ContentClean(lambda d: {"allowed": True}).check({"content": [1, 2]}).met


# ── the ladder together ─────────────────────────────────────────────────────


def _broker(inspect=lambda d: {"allowed": True}):
    return Gate("app:wiki", target="https://wiki.internal", requirements=[
        LiveSession(_Sessions({"tok": "sam"})),
        RoleGranted(_Policy({"sam": ["app:wiki:read"]}), "app:wiki:read"),
        _posture(require={"disk_encrypted": True}, max_age_s=3600),
        EgressAllowed(_Wall({"wiki.internal"})),
        ContentClean(inspect),
    ])


GOOD = {"session": "tok", "subject": "sam", "device": FIT,
        "destination": "wiki.internal", "content": b"hello"}


def test_the_full_ladder_admits_and_hands_over_the_target():
    a = _broker().admit(GOOD)
    assert a.admitted and a.target == "https://wiki.internal"
    assert [c.name for c in a.checks] == [
        "live_session", "role_granted", "device_posture", "egress_allowed",
        "content_clean"]


@pytest.mark.parametrize("change,rung", [
    ({"session": "gone"}, "live_session"),
    ({"subject": "alex", "session": ""}, "live_session"),
    ({"device": dict(FIT, disk_encrypted=False)}, "device_posture"),
    ({"destination": "evil.example"}, "egress_allowed"),
    ({"content": b"SECRET"}, "content_clean"),
])
def test_any_one_unmet_rung_closes_the_gate_and_withholds_the_target(change, rung):
    a = _broker(_inspector([])).admit(dict(GOOD, **change))
    assert not a.admitted and a.target is None
    assert rung in [c.name for c in a.failed]


def test_the_audit_record_carries_reasons_and_no_content():
    a = _broker(_inspector([])).admit(dict(GOOD, content=b"key=SECRET-abc123"))
    record = a.as_record()
    assert record["admitted"] is False and record["subject"] == "sam"
    assert "SECRET" not in str(record) and "tok" not in str(record)
