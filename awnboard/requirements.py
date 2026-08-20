"""The ladder: what a visitor must satisfy, one rung at a time.

Each requirement answers one question and returns a `Check` saying whether it was
met, why not, and what the visitor should DO about it. That last field is the one
most access systems omit, and its absence is why every denial becomes a support
conversation.

THE RULES EVERY RUNG FOLLOWS
============================
* **Unmet by default.** A requirement that cannot evaluate -- missing input, a
  checker that is not installed, a store it cannot read -- returns unmet, never
  met. There is no path through this module where an error becomes admission.
* **It says what to do next.** "Wrong code" and "this gate wants a code and you
  did not send one" are different situations for the person outside.
* **It never explains too much.** `Passcode` does not say how long the code is or
  how many tries remain; the remedy is "check the code you were sent", not a
  description of the secret.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol, Sequence

from awnboard.grant import GrantLedger, InvitationError, Signer, read_invitation

__all__ = [
    "Check", "Requirement", "Passcode", "Invited", "KnownSubject", "VerifiedHuman",
    "hash_passcode",
]


@dataclass(frozen=True)
class Check:
    """One rung's answer. `met=False` is the default everywhere it is constructed
    from a failure path."""

    name: str
    met: bool
    why: str = ""
    #: What the visitor should do. Shown to them; keep it actionable and free of
    #: anything that helps someone guess.
    remedy: str = ""
    #: Facts the gate may want to record or use later -- the invitation id it
    #: matched, the subject it resolved. Never secrets.
    detail: Optional[dict[str, Any]] = None


class Requirement(Protocol):
    """One rung. `check` is given whatever the visitor presented."""

    name: str

    def check(self, presented: Mapping[str, Any]) -> Check: ...


def hash_passcode(code: str, *, salt: str) -> str:
    """A passcode digest for storage.

    Salted and iterated rather than a bare hash: gate codes are short and
    human-typed, so an unsalted digest of "sunrise-42" is a lookup away from
    plaintext. Not a KDF competition -- `scrypt` from the stdlib, with parameters
    a gate can afford per attempt.
    """
    if not code:
        raise ValueError("a passcode must not be empty")
    if not salt:
        raise ValueError("a passcode hash needs a salt; an unsalted one is a lookup")
    return hashlib.scrypt(code.encode("utf-8"), salt=salt.encode("utf-8"),
                          n=2 ** 14, r=8, p=1, dklen=32).hex()


class Passcode:
    """The floor: something you were told, typed in.

    Weak on its own and honest about it -- a passcode is shareable, and once shared
    it is a link with extra steps. It is here because it is the rung that makes a
    gate adoptable with nothing else installed, and because "the code plus an
    invitation addressed to you" is meaningfully stronger than either.
    """

    name = "passcode"

    def __init__(self, digest: str, *, salt: str) -> None:
        if not digest:
            raise ValueError("Passcode needs the stored digest, not the code itself")
        self._digest = digest
        self._salt = salt

    def check(self, presented: Mapping[str, Any]) -> Check:
        code = str(presented.get("passcode") or "")
        if not code:
            return Check(self.name, False, "no passcode presented",
                         "This gate needs the code you were sent.")
        try:
            got = hash_passcode(code, salt=self._salt)
        except ValueError as exc:
            return Check(self.name, False, str(exc), "This gate needs the code you were sent.")
        if not hmac.compare_digest(got, self._digest):
            # Deliberately says nothing about the code's shape or how close this was.
            return Check(self.name, False, "passcode does not match",
                         "That code was not right. Check the message you were sent.")
        return Check(self.name, True)


class Invited:
    """A signed invitation that NAMES this visitor, has uses left, and is not revoked.

    The addressee comparison is the point of the whole rung: an invitation to
    `sam@example.com` presented by anyone else is refused even though the signature
    is perfect. That is what stops forwarding, and it is why the gate must know who
    the visitor claims to be (from a session, an email link, a form -- whatever the
    deployment already has).
    """

    name = "invited"

    def __init__(self, gate: str, signer: Signer, ledger: Optional[GrantLedger] = None,
                 *, match: str = "exact") -> None:
        self.gate = gate
        self.signer = signer
        self.ledger = ledger
        if match not in ("exact", "casefold"):
            raise ValueError("match must be 'exact' or 'casefold'")
        #: Email addresses arrive with arbitrary case; user ids usually must not be
        #: folded. Explicit per gate, because guessing wrong in either direction is
        #: either a lockout or a collision.
        self.match = match

    def _same(self, a: str, b: str) -> bool:
        return a.casefold() == b.casefold() if self.match == "casefold" else a == b

    def check(self, presented: Mapping[str, Any]) -> Check:
        token = str(presented.get("invitation") or "")
        if not token:
            return Check(self.name, False, "no invitation presented",
                         "This gate is by invitation. Use the link or code you were sent.")
        try:
            inv = read_invitation(token, self.signer, gate=self.gate)
        except (InvitationError, ValueError) as exc:
            return Check(self.name, False, str(exc),
                         "That invitation is not valid for this gate. Ask for a new one.")
        claimed = str(presented.get("as") or "")
        if not claimed:
            return Check(self.name, False, "the visitor did not say who they are",
                         "Sign in, or open the link from the message it was sent to.")
        if not self._same(claimed, inv.to):
            # Refused with the same message either way: naming the real addressee
            # here would turn the gate into a directory of who was invited.
            return Check(self.name, False, "invitation is addressed to someone else",
                         "That invitation was sent to someone else. Ask for your own.")
        if self.ledger is not None:
            try:
                if self.ledger.is_revoked(inv.id):
                    return Check(self.name, False, "invitation was revoked",
                                 "That invitation has been withdrawn. Ask for a new one.")
                if not self.ledger.spend(inv.id, inv.uses, who=claimed):
                    return Check(self.name, False, "invitation has no uses left",
                                 "That invitation has already been used. Ask for a new one.")
            except InvitationError as exc:
                # An unreadable ledger fails CLOSED: we cannot tell whether this
                # invitation was revoked, and "cannot tell" is not "fine".
                return Check(self.name, False, f"grant ledger unavailable: {exc}",
                             "This gate cannot check invitations right now. Try again shortly.")
        return Check(self.name, True, detail={"invitation_id": inv.id, "to": inv.to,
                                              "note": inv.note})


class KnownSubject:
    """The visitor is one of a named set -- an allowlist, resolved from a session.

    Takes the subject from the AUTHENTICATED context the gate was handed, never
    from a field the visitor typed. A gate that allowlists a self-declared name is
    a gate that anyone can walk through by typing the right name.
    """

    name = "known_subject"

    def __init__(self, allowed: Sequence[str], *, casefold: bool = False) -> None:
        self.casefold = casefold
        self._allowed = {a.casefold() if casefold else a for a in allowed}

    def check(self, presented: Mapping[str, Any]) -> Check:
        # `subject` is the resolved identity; `as` is what the visitor CLAIMED. They
        # are separate keys precisely so this rung cannot accidentally read the
        # claim -- see the class docstring.
        subject = str(presented.get("subject") or "")
        if not subject:
            return Check(self.name, False, "no authenticated subject",
                         "Sign in first, then open this link again.")
        needle = subject.casefold() if self.casefold else subject
        if needle not in self._allowed:
            return Check(self.name, False, "subject is not on this gate's list",
                         "Your account does not have access to this. Ask the owner to add you.")
        return Check(self.name, True, detail={"subject": subject})


class VerifiedHuman:
    """Is there a person there. Delegates to awnest when it is installed.

    OPTIONAL, and the import is guarded for a reason worth stating: a gate that
    cannot be built without a sibling package is not a gate you can adopt. When
    awnest is absent, this rung is UNMET rather than skipped -- a gate that quietly
    drops its strongest requirement because a dependency is missing is the exact
    silent downgrade this family exists to stop.
    """

    name = "verified_human"

    def __init__(self, audience: str, secret: str, *, max_age_s: Optional[float] = None,
                 min_score: Optional[int] = None) -> None:
        self.audience = audience
        self.secret = secret
        self.max_age_s = max_age_s
        self.min_score = min_score

    def check(self, presented: Mapping[str, Any]) -> Check:
        token = str(presented.get("attestation") or "")
        if not token:
            return Check(self.name, False, "no human check presented",
                         "Take the quick human check, then come back — it takes a minute.")
        try:
            from awnest import AttestationError, HmacKey, verify
        except ImportError:
            return Check(self.name, False,
                         "this gate requires a human check but awnest is not installed",
                         "This gate is misconfigured. Tell whoever runs it.")
        subject = str(presented.get("subject") or "") or None
        try:
            att = verify(token, HmacKey(self.secret), audience=self.audience,
                         subject=subject)
        except (AttestationError, ValueError) as exc:
            return Check(self.name, False, str(exc),
                         "That human check is not valid here. Take it again.")
        if self.max_age_s is not None and att.age_s(time.time()) > self.max_age_s:
            return Check(self.name, False, "human check has aged out for this gate",
                         "Your human check has expired. Take it again — it takes a minute.")
        if self.min_score is not None and att.score is not None and att.score < self.min_score:
            return Check(self.name, False, f"human check scored {att.score}",
                         "Take the human check again.")
        return Check(self.name, True, detail={"subject": att.sub, "score": att.score,
                                              "method": att.method})
