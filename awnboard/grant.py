"""Invitations and grants: the thing you can actually send someone.

WHY NOT A LINK
==============
Every "share link" product fails the same way, and it is worth naming precisely
because the failure looks like the feature: **the link IS the credential.**
Forwarding it transfers it. Anyone who sees a screenshot has it. It does not know
who it was for, so it cannot tell you who used it, and revoking means rotating
something everyone else is still using.

An invitation here is a signed statement that names:

    gate       which door -- so one invitation cannot open another gate
    to         WHO it is for -- an email, a user id, a phone number, anything the
               gate can later match. This is the field a link does not have, and
               it is why forwarding stops working.
    uses       how many times. One, usually.
    exp        until when.
    id         so it can be revoked ALONE, without touching anyone else's.

Send it in an email, a chat message, a QR code, a letter. It is text.

REVOCATION IS PER GRANT OR IT IS NOT REVOCATION
===============================================
`GrantLedger` records each acceptance and each revocation by invitation id. The
alternative -- rotating the gate's key -- revokes everybody, which is why nobody
does it, which is why the invitation you regret stays live.

WHAT THIS DELIBERATELY IS NOT
=============================
It is not a verdict about a person. "This invitation names Sam" and "the caller is
a human" and "the caller is Sam" are three different claims with three different
lifetimes, and a format that carried all three would make all three expire
together. The gate composes them; the invitation stays one claim.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "Invitation", "InvitationError", "Signer", "HmacSigner",
    "invite", "read_invitation", "GrantLedger", "INVITATION_FIELDS", "TOKEN_PREFIX",
]

#: Versioned, so a format change is a loud refusal in an old gate rather than a
#: signature failure it would report as tampering.
TOKEN_PREFIX = "awb1"

#: EXACTLY the fields, in order. A constant the self-test asserts against, because
#: a field missing HERE does not raise -- it produces an invitation that verifies
#: perfectly and no longer says who it was for.
INVITATION_FIELDS = ("v", "alg", "gate", "to", "uses", "iat", "exp", "id", "note")


class InvitationError(RuntimeError):
    """This invitation does not hold. Raised, never returned as a falsy object."""


@dataclass(frozen=True)
class Invitation:
    """A verified invitation. Only ever produced by `read_invitation`."""

    gate: str
    to: str
    uses: int
    iat: float
    exp: float
    id: str
    note: str = ""
    alg: str = "hs256"
    v: int = 1


class Signer:
    """Something that signs and checks. `alg` is authoritative -- the token names an
    algorithm and the SIGNER decides it, so a mismatch is a refusal rather than an
    invitation to let the sender pick the weakest one."""

    alg = "hs256"

    def sign(self, msg: bytes) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def check(self, msg: bytes, sig: bytes) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


class HmacSigner(Signer):
    """Shared-secret signing: whoever can check can also issue. Fine for a gate you
    run; wrong if a third party must verify without being able to invite."""

    alg = "hs256"

    def __init__(self, secret: bytes | str) -> None:
        raw = secret.encode("utf-8") if isinstance(secret, str) else secret
        if len(raw) < 16:
            raise ValueError(
                "a gate secret under 16 bytes is guessable, and a guessable key makes "
                "every rule here decorative"
            )
        self._secret = raw

    def sign(self, msg: bytes) -> bytes:
        return hmac.new(self._secret, msg, hashlib.sha256).digest()

    def check(self, msg: bytes, sig: bytes) -> bool:
        # compare_digest, never ==: a timing-variable signature comparison is a
        # forgery oracle and it is one character to get wrong.
        return hmac.compare_digest(self.sign(msg), sig)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(txt: str) -> bytes:
    return base64.urlsafe_b64decode(txt + "=" * (-len(txt) % 4))


def payload_for(*, gate: str, to: str, uses: int, iat: float, ttl_s: float,
                inv_id: str, note: str, alg: str) -> dict[str, Any]:
    """The signed body. Pure, so the field set is testable with no key and no clock."""
    if not gate:
        raise ValueError("an invitation with no gate opens whichever one it is shown to")
    if not to:
        raise ValueError(
            "an invitation with no addressee is a share link: forwarding it transfers "
            "it, and nothing can tell you who walked through"
        )
    if uses < 1:
        raise ValueError("an invitation good for zero uses admits nobody")
    if ttl_s <= 0:
        raise ValueError("an invitation must expire; ttl_s must be positive")
    return {"v": 1, "alg": alg, "gate": gate, "to": to, "uses": int(uses),
            "iat": iat, "exp": iat + ttl_s, "id": inv_id, "note": note}


def invite(signer: Signer, *, gate: str, to: str, uses: int = 1,
           ttl_s: float = 7 * 24 * 3600.0, note: str = "",
           now: Optional[float] = None, inv_id: Optional[str] = None) -> str:
    """Create an invitation. Returns the token -- text you can put in an email."""
    iat = time.time() if now is None else now
    body = payload_for(gate=gate, to=to, uses=uses, iat=iat, ttl_s=ttl_s,
                       inv_id=inv_id or secrets.token_urlsafe(12), note=note,
                       alg=signer.alg)
    # Canonical bytes: sorted keys, no spaces. Re-serialising a parsed payload has
    # to produce the same bytes or verification becomes interpreter-dependent.
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signed = f"{TOKEN_PREFIX}.{_b64(raw)}"
    return f"{signed}.{_b64(signer.sign(signed.encode('ascii')))}"


def read_invitation(token: str, signer: Signer, *, gate: str,
                    now: Optional[float] = None) -> Invitation:
    """Verify an invitation against THIS gate. Returns it, or raises.

    `gate` is required: reading an invitation without naming the door accepts one
    issued for a different door, which is the whole reason the field exists.
    """
    if not gate:
        raise ValueError("read_invitation() needs the gate being opened")
    parts = (token or "").split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise InvitationError("not an awnboard invitation (or a different format version)")
    try:
        body = json.loads(_unb64(parts[1]))
        sig = _unb64(parts[2])
    except Exception as exc:
        raise InvitationError(f"invitation is not decodable: {exc}") from exc
    if not isinstance(body, dict):
        raise InvitationError("invitation payload is not an object")
    missing = [f for f in INVITATION_FIELDS if f not in body]
    if missing:
        # Refuse rather than default: a missing `to` defaulted to "anyone" is the
        # share link this format exists to replace.
        raise InvitationError(f"invitation is missing required field(s): {missing}")
    if body["alg"] != signer.alg:
        raise InvitationError(
            f"invitation claims alg={body['alg']!r} but this gate holds a {signer.alg!r} "
            "key -- refusing rather than trusting the token's claim"
        )
    if not signer.check(f"{parts[0]}.{parts[1]}".encode("ascii"), sig):
        raise InvitationError("signature does not verify")
    t = time.time() if now is None else now
    if body["gate"] != gate:
        raise InvitationError(
            f"invitation is for gate {body['gate']!r}, not {gate!r}"
        )
    if float(body["exp"]) < t:
        raise InvitationError("invitation has expired")
    if float(body["iat"]) > t + 60:
        raise InvitationError("invitation is dated in the future -- refused, not held")
    return Invitation(gate=body["gate"], to=str(body["to"]), uses=int(body["uses"]),
                      iat=float(body["iat"]), exp=float(body["exp"]), id=str(body["id"]),
                      note=str(body.get("note", "")), alg=str(body["alg"]),
                      v=int(body["v"]))


class GrantLedger:
    """Who used what, and what has been revoked. One JSON file, one lock-free write.

    Deliberately a FILE and not a database: a gate in front of one thing should not
    require anyone to run a service, and the moment it does, people put the gate
    somewhere else. The interface is small enough to reimplement over Redis or
    Postgres when a deployment needs it.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"used": {}, "revoked": {}}
        except (OSError, ValueError) as exc:
            # An unreadable ledger must NOT read as an empty one: empty means
            # "nothing revoked, nothing spent", which silently un-revokes every
            # grant and re-opens every one-use invitation.
            raise InvitationError(f"grant ledger at {self.path} is unreadable: {exc}") from exc

    def _write(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)      # atomic: a torn ledger is a broken gate

    def revoke(self, invitation_id: str, reason: str = "") -> None:
        """Revoke ONE invitation. Everyone else's keeps working -- which is the only
        version of revocation anybody actually performs."""
        data = self._read()
        data["revoked"][invitation_id] = {"at": time.time(), "reason": reason}
        self._write(data)

    def is_revoked(self, invitation_id: str) -> bool:
        return invitation_id in self._read()["revoked"]

    def spend(self, invitation_id: str, limit: int, who: str = "") -> bool:
        """Record one use. False when the invitation is spent or revoked.

        Read-modify-write on one file, so two SIMULTANEOUS acceptances of a
        one-use invitation can both succeed. That is stated rather than hidden: the
        window is small, the consequence is one extra admission, and pretending
        otherwise would be worse than saying so. A deployment that cannot accept it
        wants a ledger with a real compare-and-set behind this same interface.
        """
        data = self._read()
        if invitation_id in data["revoked"]:
            return False
        entry = data["used"].setdefault(invitation_id, {"count": 0, "who": []})
        if entry["count"] >= limit:
            return False
        entry["count"] += 1
        if who:
            entry["who"].append({"who": who, "at": time.time()})
        self._write(data)
        return True

    def uses(self, invitation_id: str) -> int:
        return int(self._read()["used"].get(invitation_id, {}).get("count", 0))

    def history(self, invitation_id: str) -> list[dict[str, Any]]:
        """Who walked through, and when. The question a share link cannot answer."""
        return list(self._read()["used"].get(invitation_id, {}).get("who", []))
