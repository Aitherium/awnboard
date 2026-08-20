"""Tests for awnboard.

The CLI's `--self-test` proves the same invariants with no pytest, so the package
can prove itself on a bare machine. This file adds what needs a real filesystem
and the cases that are easier to read as separate named facts.
"""
from __future__ import annotations

import json

import pytest
from awnboard import (
    Gate,
    GateError,
    GrantLedger,
    HmacSigner,
    InvitationError,
    Invited,
    KnownSubject,
    Passcode,
    VerifiedHuman,
    hash_passcode,
    invite,
    read_invitation,
)

SECRET = "a-test-secret-that-is-long-enough"
T = 1_700_000_000.0


@pytest.fixture()
def signer():
    return HmacSigner(SECRET)


@pytest.fixture()
def ledger(tmp_path):
    return GrantLedger(tmp_path / "grants.json")


# ── the invitation ─────────────────────────────────────────────────────────


def test_an_invitation_names_its_recipient(signer):
    tok = invite(signer, gate="beta", to="sam@example.com", now=T, inv_id="i1")
    assert read_invitation(tok, signer, gate="beta", now=T + 5).to == "sam@example.com"


def test_an_invitation_for_one_gate_does_not_open_another(signer):
    tok = invite(signer, gate="beta", to="sam@example.com", now=T)
    with pytest.raises(InvitationError):
        read_invitation(tok, signer, gate="production", now=T + 5)


def test_an_invitation_without_an_addressee_cannot_be_issued(signer):
    with pytest.raises(ValueError):
        invite(signer, gate="beta", to="", now=T)


def test_a_short_secret_is_refused():
    with pytest.raises(ValueError):
        HmacSigner("short")


# ── the ladder ─────────────────────────────────────────────────────────────


def test_forwarding_does_not_transfer_access(signer, ledger):
    gate = Gate("beta", target="https://x.invalid", requirements=[Invited("beta", signer, ledger)])
    tok = invite(signer, gate="beta", to="sam@example.com")
    assert gate.admit({"invitation": tok, "as": "sam@example.com"}).admitted
    tok2 = invite(signer, gate="beta", to="sam@example.com")
    forwarded = gate.admit({"invitation": tok2, "as": "mallory@example.com"})
    assert not forwarded.admitted
    # ...and the refusal does not tell Mallory who it WAS for.
    assert "sam@example.com" not in forwarded.message()


def test_one_use_is_one_use(signer, ledger):
    gate = Gate("beta", requirements=[Invited("beta", signer, ledger)])
    tok = invite(signer, gate="beta", to="sam@example.com", uses=1, inv_id="one")
    assert gate.admit({"invitation": tok, "as": "sam@example.com"}).admitted
    assert not gate.admit({"invitation": tok, "as": "sam@example.com"}).admitted


def test_revocation_is_per_invitation(signer, ledger):
    gate = Gate("beta", requirements=[Invited("beta", signer, ledger)])
    mine = invite(signer, gate="beta", to="ana@example.com", uses=5, inv_id="mine")
    yours = invite(signer, gate="beta", to="lee@example.com", uses=5, inv_id="yours")
    assert gate.admit({"invitation": mine, "as": "ana@example.com"}).admitted
    ledger.revoke("mine", reason="left the project")
    assert not gate.admit({"invitation": mine, "as": "ana@example.com"}).admitted
    assert gate.admit({"invitation": yours, "as": "lee@example.com"}).admitted


def test_the_ledger_records_who_walked_through(signer, ledger):
    gate = Gate("beta", requirements=[Invited("beta", signer, ledger)])
    tok = invite(signer, gate="beta", to="ana@example.com", uses=2, inv_id="k")
    gate.admit({"invitation": tok, "as": "ana@example.com"})
    who = ledger.history("k")
    assert len(who) == 1 and who[0]["who"] == "ana@example.com"


def test_an_unreadable_ledger_fails_closed(signer, tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    gate = Gate("beta", requirements=[Invited("beta", signer, GrantLedger(path))])
    tok = invite(signer, gate="beta", to="ana@example.com")
    assert not gate.admit({"invitation": tok, "as": "ana@example.com"}).admitted


def test_the_ledger_survives_being_a_real_file(signer, tmp_path):
    a = GrantLedger(tmp_path / "g.json")
    a.revoke("x", "because")
    b = GrantLedger(tmp_path / "g.json")     # a second process would look like this
    assert b.is_revoked("x")
    assert json.loads((tmp_path / "g.json").read_text(encoding="utf-8"))["revoked"]["x"]


def test_every_rung_must_be_met():
    salt = "s" * 16
    gate = Gate("b", requirements=[Passcode(hash_passcode("code-me", salt=salt), salt=salt),
                                   KnownSubject(["u1"])])
    assert not gate.admit({"passcode": "code-me"}).admitted
    assert not gate.admit({"subject": "u1"}).admitted
    assert gate.admit({"passcode": "code-me", "subject": "u1"}).admitted


def test_a_gate_with_no_requirements_is_refused_at_construction():
    with pytest.raises(GateError):
        Gate("open", requirements=[])


def test_an_allowlist_reads_the_authenticated_subject_not_the_claim():
    gate = Gate("k", requirements=[KnownSubject(["u1"])])
    assert not gate.admit({"as": "u1"}).admitted        # typed
    assert gate.admit({"subject": "u1"}).admitted       # resolved


def test_a_requirement_that_raises_is_unmet():
    class Boom:
        name = "boom"

        def check(self, presented):
            raise RuntimeError("kaboom")

    a = Gate("x", requirements=[Boom()]).admit({})
    assert not a.admitted
    assert "raised" in a.reasons()


def test_the_human_rung_is_unmet_rather_than_skipped():
    rung = VerifiedHuman("app:x", "a-secret-that-is-long-enough")
    assert not rung.check({}).met
    assert not rung.check({"attestation": "nonsense"}).met


def test_a_refusal_carries_a_remedy_for_the_visitor_and_a_reason_for_the_operator(signer):
    gate = Gate("beta", requirements=[Invited("beta", signer, None)])
    a = gate.admit({})
    assert not a.admitted
    assert a.message() and "invitation" in a.message().lower()
    assert "invited:" in a.reasons()


def test_the_audit_record_carries_no_tokens(signer, ledger):
    gate = Gate("beta", requirements=[Invited("beta", signer, ledger)])
    tok = invite(signer, gate="beta", to="ana@example.com")
    rec = gate.admit({"invitation": tok, "as": "ana@example.com"}).as_record()
    assert tok not in json.dumps(rec)


def test_a_passcode_digest_is_salted():
    assert hash_passcode("x", salt="a" * 16) != hash_passcode("x", salt="b" * 16)
    with pytest.raises(ValueError):
        hash_passcode("x", salt="")
