"""awnboard CLI.

    awnboard invite  --gate beta --to sam@example.com --uses 1 --ttl 604800
    awnboard read    TOKEN --gate beta
    awnboard admit   --gate beta --invitation TOKEN --as sam@example.com [--passcode X]
    awnboard revoke  INVITATION_ID --reason "left the project"
    awnboard history INVITATION_ID
    awnboard hash    --code sunrise-42 --salt <salt>
    awnboard --self-test

The signing secret comes from --secret or AWNBOARD_SECRET, and the ledger from
--ledger or AWNBOARD_LEDGER. Neither is guessed: a gate that falls back to a
default key is a gate anyone who knows the default can invite themselves through.

Exit codes:  0 admitted / ok      1 refused or broke      2 you asked wrongly
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from awnboard.gate import Gate, GateError
from awnboard.grant import (
    INVITATION_FIELDS,
    GrantLedger,
    HmacSigner,
    InvitationError,
    invite,
    payload_for,
    read_invitation,
)
from awnboard.requirements import (
    Check,
    Invited,
    KnownSubject,
    Passcode,
    VerifiedHuman,
    hash_passcode,
)

_SECRET_ENV = "AWNBOARD_SECRET"
_LEDGER_ENV = "AWNBOARD_LEDGER"


# ── self-test ──────────────────────────────────────────────────────────────
# Pure except for one temporary directory: the ledger's job is to survive being a
# real file, and asserting it against a dict would prove nothing about the thing
# that actually runs.


def _raises(fn, *args, **kwargs) -> bool:
    try:
        fn(*args, **kwargs)
    except (ValueError, InvitationError, GateError):
        return True
    return False


def _self_test() -> int:  # noqa: C901 - a flat list of independent assertions
    import tempfile

    f: list[str] = []
    t = 1_700_000_000.0
    signer = HmacSigner("self-test-secret-not-a-real-key")

    # 1. An invitation carries EXACTLY the fields that make it not-a-link. The one
    #    that matters is `to`: without it, forwarding transfers access.
    body = payload_for(gate="g", to="sam@example.com", uses=1, iat=t, ttl_s=60,
                       inv_id="i1", note="", alg="hs256")
    if tuple(body) != INVITATION_FIELDS:
        f.append(f"invitation keys {tuple(body)} != declared {INVITATION_FIELDS}")
    for kwargs, why in (({"gate": ""}, "no gate"), ({"to": ""}, "no addressee"),
                        ({"uses": 0}, "zero uses"), ({"ttl_s": 0}, "no expiry")):
        args = dict(gate="g", to="sam@example.com", uses=1, iat=t, ttl_s=60,
                    inv_id="i1", note="", alg="hs256")
        args.update(kwargs)
        if not _raises(payload_for, **args):
            f.append(f"issued an invitation with {why}")

    # 2. Round trip, and every way it must not.
    tok = invite(signer, gate="beta", to="sam@example.com", uses=1, ttl_s=3600,
                 now=t, inv_id="inv-1")
    inv = read_invitation(tok, signer, gate="beta", now=t + 10)
    if inv.to != "sam@example.com" or inv.id != "inv-1":
        f.append("a valid invitation did not survive its round trip")
    if not _raises(read_invitation, tok, signer, gate="other", now=t + 10):
        f.append("an invitation for one gate opened another")
    if not _raises(read_invitation, tok, signer, gate="beta", now=t + 7200):
        f.append("an expired invitation was accepted")
    if not _raises(read_invitation, tok, HmacSigner("a-completely-different-key"),
                   gate="beta", now=t + 10):
        f.append("an invitation verified under the wrong key")
    head, payload, sig = tok.split(".")
    tampered = f"{head}.{payload}.{sig[:-2]}{'AB' if sig[-2:] != 'AB' else 'AC'}"
    if not _raises(read_invitation, tampered, signer, gate="beta", now=t + 10):
        f.append("a tampered invitation verified")

    # From here the fixtures are minted on the REAL clock: `Invited.check` verifies
    # against wall time, so an invitation dated 2023 is correctly expired. Feeding a
    # gate a fake clock would test a code path nothing runs.
    with tempfile.TemporaryDirectory() as d:
        ledger = GrantLedger(os.path.join(d, "grants.json"))
        rung = Invited("beta", signer, ledger, match="casefold")
        gate = Gate("beta", target="https://example.invalid/app", requirements=[rung])

        # 3. THE POINT OF THE WHOLE PACKAGE: forwarding does not work.
        tok_live = invite(signer, gate="beta", to="sam@example.com", uses=1,
                          ttl_s=3600, inv_id="inv-1")
        a = gate.admit({"invitation": tok_live, "as": "sam@example.com"})
        if not a.admitted or a.target != "https://example.invalid/app":
            f.append(f"the addressee was refused their own invitation: {a.reasons()}")
        tok2 = invite(signer, gate="beta", to="sam@example.com", uses=1, ttl_s=3600,
                      inv_id="inv-2")
        b = gate.admit({"invitation": tok2, "as": "someone.else@example.com"})
        if b.admitted:
            f.append("a FORWARDED invitation admitted somebody else -- this is the "
                     "share-link failure the format exists to remove")
        if "someone else" not in b.message().lower() and not b.message():
            f.append("a refusal told the visitor nothing they could act on")
        if b.message().find("sam@example.com") >= 0:
            f.append("a refusal named the real addressee -- the gate is now a directory")

        # 4. One use means one use, and revocation is per invitation.
        again = gate.admit({"invitation": tok_live, "as": "sam@example.com"})
        if again.admitted:
            f.append("a one-use invitation was spent twice")
        tok3 = invite(signer, gate="beta", to="ana@example.com", uses=3, ttl_s=3600,
                      inv_id="inv-3")
        if not gate.admit({"invitation": tok3, "as": "ana@example.com"}).admitted:
            f.append("a multi-use invitation failed on its first use")
        ledger.revoke("inv-3", reason="left the project")
        if gate.admit({"invitation": tok3, "as": "ana@example.com"}).admitted:
            f.append("a REVOKED invitation still admitted -- revocation does nothing")
        tok4 = invite(signer, gate="beta", to="lee@example.com", uses=1, ttl_s=3600,
                      inv_id="inv-4")
        if not gate.admit({"invitation": tok4, "as": "lee@example.com"}).admitted:
            f.append("revoking ONE invitation revoked somebody else's -- that is a key "
                     "rotation wearing a revoke button")
        if not ledger.history("inv-1"):
            f.append("the ledger cannot say who walked through, which a link also cannot")

        # 5. Case handling is explicit, in both directions.
        tok5 = invite(signer, gate="beta", to="Mixed@Example.com", uses=1, ttl_s=3600,
                      inv_id="inv-5")
        if not gate.admit({"invitation": tok5, "as": "mixed@example.com"}).admitted:
            f.append("a casefold gate refused an address differing only in case")
        strict = Gate("beta", requirements=[Invited("beta", signer, None, match="exact")])
        tok6 = invite(signer, gate="beta", to="Exact@Example.com", uses=1, ttl_s=3600,
                      inv_id="inv-6")
        if strict.admit({"invitation": tok6, "as": "exact@example.com"}).admitted:
            f.append("an exact-match gate folded case anyway")

        # 6. An unreadable ledger fails CLOSED. Read as empty, it would un-revoke
        #    everything and re-open every one-use invitation at once.
        broken = os.path.join(d, "broken.json")
        with open(broken, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        bad_gate = Gate("beta", requirements=[Invited("beta", signer, GrantLedger(broken))])
        tok7 = invite(signer, gate="beta", to="kim@example.com", uses=1, ttl_s=3600,
                      inv_id="inv-7")
        if bad_gate.admit({"invitation": tok7, "as": "kim@example.com"}).admitted:
            f.append("a gate with an UNREADABLE ledger admitted -- 'cannot tell' is not 'fine'")

    # 7. The ladder is ALL rungs, and a gate with no rungs is refused at build.
    salt = "s" * 16
    digest = hash_passcode("sunrise-42", salt=salt)
    both = Gate("b", requirements=[Passcode(digest, salt=salt),
                                   KnownSubject(["u1"])])
    if both.admit({"passcode": "sunrise-42"}).admitted:
        f.append("a gate admitted with one of two rungs met")
    if both.admit({"passcode": "wrong", "subject": "u1"}).admitted:
        f.append("a wrong passcode was accepted")
    if not both.admit({"passcode": "sunrise-42", "subject": "u1"}).admitted:
        f.append("both rungs met and the gate still refused")
    if not _raises(Gate, "empty", requirements=[]):
        f.append("a gate with NO requirements was built -- that is a door standing open")
    if "sunrise" in both.admit({"passcode": "x", "subject": "u1"}).message().lower():
        f.append("a refusal message quoted the secret it was checking")

    # 8. KnownSubject reads the RESOLVED subject, never the visitor's claim.
    only = Gate("k", requirements=[KnownSubject(["u1"])])
    if only.admit({"as": "u1"}).admitted:
        f.append("an allowlist was satisfied by a name the visitor TYPED")
    if not only.admit({"subject": "u1"}).admitted:
        f.append("an allowlist refused its own member")

    # 9. A rung that throws is UNMET, not a 500 somebody wraps in a try that admits.
    class _Exploding:
        name = "explodes"

        def check(self, presented):
            raise RuntimeError("kaboom")

    if Gate("x", requirements=[_Exploding()]).admit({}).admitted:
        f.append("a requirement that raised was treated as met")

    # 10. The human rung is UNMET when awnest is absent -- never skipped.
    vh = VerifiedHuman("app:x", "a-secret-that-is-long-enough")
    if vh.check({}).met:
        f.append("the human rung passed with nothing presented")
    c = vh.check({"attestation": "not-a-real-token"})
    if c.met:
        f.append("the human rung accepted a token it could not verify")
    if not isinstance(c, Check):
        f.append("a requirement returned something that is not a Check")

    # 11. Passcode storage is salted -- an unsalted digest of a short human code is
    #     a lookup away from plaintext.
    if not _raises(hash_passcode, "code", salt=""):
        f.append("a passcode was hashed with no salt")
    if hash_passcode("a", salt="s1" * 8) == hash_passcode("a", salt="s2" * 8):
        f.append("the salt does not change the digest")

    if f:
        print("SELF-TEST FAILURES:")
        for line in f:
            print("  x " + line)
        return 1
    print("awnboard self-test: ok")
    return 0


# ── commands ───────────────────────────────────────────────────────────────


def _signer(args: argparse.Namespace) -> HmacSigner:
    s = args.secret or os.environ.get(_SECRET_ENV, "")
    if not s:
        raise SystemExit(
            f"no gate secret: pass --secret or set {_SECRET_ENV}. Not defaulted on "
            "purpose -- a default key is a key everybody has."
        )
    return HmacSigner(s)


def _ledger(args: argparse.Namespace) -> Optional[GrantLedger]:
    path = getattr(args, "ledger", None) or os.environ.get(_LEDGER_ENV, "")
    return GrantLedger(path) if path else None


def _cmd_invite(args: argparse.Namespace) -> int:
    try:
        token = invite(_signer(args), gate=args.gate, to=args.to, uses=args.uses,
                       ttl_s=args.ttl, note=args.note)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(token)
    return 0


def _cmd_read(args: argparse.Namespace) -> int:
    try:
        inv = read_invitation(args.token, _signer(args), gate=args.gate)
    except InvitationError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"gate": inv.gate, "to": inv.to, "uses": inv.uses, "id": inv.id,
                      "note": inv.note, "expires_at": inv.exp}, indent=2))
    return 0


def _cmd_admit(args: argparse.Namespace) -> int:
    reqs = []
    if args.invitation:
        reqs.append(Invited(args.gate, _signer(args), _ledger(args),
                            match="casefold" if args.casefold else "exact"))
    if args.passcode_digest:
        reqs.append(Passcode(args.passcode_digest, salt=args.salt or ""))
    if args.allow:
        reqs.append(KnownSubject(args.allow))
    if not reqs:
        print("nothing to check: pass --invitation, --passcode-digest or --allow",
              file=sys.stderr)
        return 2
    try:
        gate = Gate(args.gate, target=args.target, requirements=reqs)
    except GateError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    a = gate.admit({"invitation": args.invitation or "", "as": getattr(args, "as_") or "",
                    "subject": args.subject or "", "passcode": args.passcode or ""})
    if a.admitted:
        print(json.dumps({"admitted": True, "gate": a.gate, "target": a.target,
                          "subject": a.subject}, indent=2))
        return 0
    print(f"REFUSED at {a.gate}: {a.message()}", file=sys.stderr)
    print(f"  reasons: {a.reasons()}", file=sys.stderr)
    return 1


def _cmd_revoke(args: argparse.Namespace) -> int:
    ledger = _ledger(args)
    if ledger is None:
        print(f"no ledger: pass --ledger or set {_LEDGER_ENV}. Revocation needs "
              "somewhere to be written down.", file=sys.stderr)
        return 2
    ledger.revoke(args.invitation_id, reason=args.reason)
    print(f"revoked {args.invitation_id}")
    return 0


def _cmd_history(args: argparse.Namespace) -> int:
    ledger = _ledger(args)
    if ledger is None:
        print(f"no ledger: pass --ledger or set {_LEDGER_ENV}.", file=sys.stderr)
        return 2
    print(json.dumps({"invitation_id": args.invitation_id,
                      "uses": ledger.uses(args.invitation_id),
                      "revoked": ledger.is_revoked(args.invitation_id),
                      "who": ledger.history(args.invitation_id)}, indent=2))
    return 0


def _cmd_hash(args: argparse.Namespace) -> int:
    try:
        print(hash_passcode(args.code, salt=args.salt))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="awnboard", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--self-test", action="store_true", help="prove this package can still fail")
    p.add_argument("--secret", default=None, help=f"gate signing secret (or {_SECRET_ENV})")
    p.add_argument("--ledger", default=None, help=f"grant ledger path (or {_LEDGER_ENV})")
    sub = p.add_subparsers(dest="cmd")

    i = sub.add_parser("invite", help="create an invitation addressed to one person")
    i.add_argument("--gate", required=True)
    i.add_argument("--to", required=True, help="who it is for -- email, user id, handle")
    i.add_argument("--uses", type=int, default=1)
    i.add_argument("--ttl", type=float, default=7 * 24 * 3600.0)
    i.add_argument("--note", default="")
    i.set_defaults(fn=_cmd_invite)

    r = sub.add_parser("read", help="verify an invitation without spending it")
    r.add_argument("token")
    r.add_argument("--gate", required=True)
    r.set_defaults(fn=_cmd_read)

    a = sub.add_parser("admit", help="run the ladder and admit or refuse")
    a.add_argument("--gate", required=True)
    a.add_argument("--target", default=None)
    a.add_argument("--invitation", default=None)
    a.add_argument("--as", dest="as_", default=None, help="who the visitor CLAIMS to be")
    a.add_argument("--subject", default=None, help="the AUTHENTICATED identity, if any")
    a.add_argument("--passcode", default=None)
    a.add_argument("--passcode-digest", default=None, help="from `awnboard hash`")
    a.add_argument("--salt", default=None)
    a.add_argument("--allow", action="append", default=None, help="allowlisted subject")
    a.add_argument("--casefold", action="store_true", help="fold case on the addressee")
    a.set_defaults(fn=_cmd_admit)

    v = sub.add_parser("revoke", help="revoke ONE invitation")
    v.add_argument("invitation_id")
    v.add_argument("--reason", default="")
    v.set_defaults(fn=_cmd_revoke)

    h = sub.add_parser("history", help="who walked through, and when")
    h.add_argument("invitation_id")
    h.set_defaults(fn=_cmd_history)

    hp = sub.add_parser("hash", help="hash a passcode for storage")
    hp.add_argument("--code", required=True)
    hp.add_argument("--salt", required=True)
    hp.set_defaults(fn=_cmd_hash)

    args = p.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not getattr(args, "fn", None):
        p.print_help()
        return 2
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())
