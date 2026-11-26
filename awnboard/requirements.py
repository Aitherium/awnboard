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

THE ACCESS RUNGS
================
`LiveSession`, `RoleGranted`, `DevicePosture`, `EgressAllowed` and `ContentClean`
turn a gate into an access broker: who is asking, whether their role covers this,
whether the device they are on is fit, whether the destination is allowed, and
whether what they are sending may leave. Each one is handed the thing that knows
the answer -- a session store, a role policy, an allowlist, an inspector -- and
only asks it. None of them imports a sibling package: a store with the right
method is enough, so each rung is usable with whatever you already run.

Everything those rungs read (`subject`, `device`, `destination`, `content`) must
be put into `presented` by YOUR code from an authenticated request. A gate that
reads a device's encryption state from a field the visitor typed is a gate that
believes whatever it is told.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Protocol, Sequence

from awnboard.grant import GrantLedger, InvitationError, Signer, read_invitation

__all__ = [
    "Check", "Requirement", "Passcode", "Invited", "KnownSubject", "VerifiedHuman",
    "LiveSession", "RoleGranted", "DevicePosture", "EgressAllowed", "ContentClean",
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


# ── the access rungs ────────────────────────────────────────────────────────


class LiveSession:
    """The visitor's session is live RIGHT NOW.

    Asked of the session store on every admission, never read out of a token that
    was valid when it was minted. That is the difference between "we disabled the
    account" and "we disabled the account and it stopped working".

    Takes any store whose ``resolve(token)`` answers with ``ok``, ``subject_id``
    and ``reason`` -- awiam's ``Sessions`` is one. When the gate was also handed a
    resolved ``subject``, the session must be THAT subject's: a live session for
    somebody else is not a credential for this visitor.
    """

    name = "live_session"

    def __init__(self, sessions: Any) -> None:
        self._sessions = sessions

    def check(self, presented: Mapping[str, Any]) -> Check:
        token = str(presented.get("session") or "")
        if not token:
            return Check(self.name, False, "no session presented",
                         "Sign in first, then open this link again.")
        res = self._sessions.resolve(token)
        if getattr(res, "ok", False) is not True:
            return Check(self.name, False,
                         str(getattr(res, "reason", "") or "session did not resolve"),
                         "Your session has ended. Sign in again.")
        owner = str(getattr(res, "subject_id", "") or "")
        if not owner:
            return Check(self.name, False, "session resolved to no subject",
                         "Your session has ended. Sign in again.")
        subject = str(presented.get("subject") or "")
        if subject and subject != owner:
            return Check(self.name, False, "session belongs to a different subject",
                         "Sign in again as yourself, then open this link again.")
        return Check(self.name, True, detail={"subject": owner})


class RoleGranted:
    """The visitor's role covers this permission.

    Takes any policy whose ``check(subject, permission)`` answers with ``allowed``
    and ``reason`` -- awbac's ``Policy`` is one. The subject comes from the
    authenticated context, exactly as `KnownSubject` reads it. The policy's own
    explanation goes to the operator; the visitor is told only that they lack
    access, because naming the role they are missing is a map of what to ask for.
    """

    name = "role_granted"

    def __init__(self, policy: Any, permission: str) -> None:
        if not permission:
            raise ValueError("a role rung needs the permission it guards -- one that "
                             "names nothing would be satisfied by any grant")
        self._policy = policy
        self.permission = permission

    def check(self, presented: Mapping[str, Any]) -> Check:
        subject = str(presented.get("subject") or "")
        if not subject:
            return Check(self.name, False, "no authenticated subject",
                         "Sign in first, then open this link again.")
        decision = self._policy.check(subject, self.permission)
        # `allowed is True`, not truthiness: a policy that answers with a tuple or
        # a non-empty string would otherwise read as a yes.
        if getattr(decision, "allowed", False) is not True:
            return Check(self.name, False,
                         str(getattr(decision, "reason", "") or "permission not granted"),
                         "Your account does not have access to this. Ask the owner to add you.")
        return Check(self.name, True, detail={"subject": subject,
                                              "permission": self.permission,
                                              "via": getattr(decision, "via", None)})


_VERSION_RE = re.compile(r"v?(\d+(?:[.\-]\d+){0,7})")


def _version_key(value: Any) -> Optional[tuple[int, ...]]:
    """A bare version or ISO date as a comparable tuple.

    ``"14.2"`` -> ``(14, 2)``, ``"2026-09-05"`` -> ``(2026, 9, 5)``. None for
    anything that is not ONLY a version, which the caller treats as "not
    reported". ``"Phone15,2 OS 12"`` is not read as 15: picking digits out of
    free text finds a model number as readily as a version, so the caller
    normalises the attribute before it gets here.
    """
    m = _VERSION_RE.fullmatch(str(value if value is not None else "").strip().lower())
    return tuple(int(p) for p in re.split(r"[.\-]", m.group(1))) if m else None


def _older(have: tuple[int, ...], floor: tuple[int, ...]) -> bool:
    # Padded to one length first: unpadded, (14,) sorts BELOW (14, 0) and a device
    # on "14" would be refused by a floor of "14.0".
    width = max(len(have), len(floor))
    return have + (0,) * (width - len(have)) < floor + (0,) * (width - len(floor))


class DevicePosture:
    """The device the visitor is on is fit to be let in.

    ``require`` is facts that must match exactly (``{"disk_encrypted": True}``),
    ``at_least`` is version or date floors (``{"os_version": "14",
    "patch_level": "2026-09-01"}``), and ``max_age_s`` bounds how old the device's
    last report may be, read from its ``reported_at`` (epoch seconds).

    An attribute the device did NOT report is unmet. "We do not know whether the
    disk is encrypted" is not "the disk is encrypted", and a posture check that
    passes the devices it knows least about checks nothing.

    The ``device`` mapping must come from YOUR enrolment record for an
    authenticated device, never from the request body.
    """

    name = "device_posture"
    #: A report this far in the future is a wrong clock or a forged record, and
    #: either way it must not read as "fresh forever".
    FUTURE_SKEW_S = 300.0

    def __init__(self, *, require: Optional[Mapping[str, Any]] = None,
                 at_least: Optional[Mapping[str, Any]] = None,
                 max_age_s: Optional[float] = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.require = dict(require or {})
        self.at_least = {k: str(v) for k, v in (at_least or {}).items()}
        self.max_age_s = max_age_s
        self._clock = clock
        if not self.require and not self.at_least and max_age_s is None:
            raise ValueError("a posture rung that requires nothing admits every device "
                             "-- name at least one fact, floor or freshness bound")
        for key, floor in self.at_least.items():
            if _version_key(floor) is None:
                raise ValueError(f"at_least[{key!r}] = {floor!r} has no number to compare")

    def check(self, presented: Mapping[str, Any]) -> Check:
        device = presented.get("device")
        if not isinstance(device, Mapping) or not device:
            return Check(self.name, False, "no enrolled device presented",
                         "Open this from a device enrolled with your organisation.")
        failed: list[str] = []
        for key, want in self.require.items():
            if key not in device:
                failed.append(f"{key}: not reported")
            elif device[key] != want:
                failed.append(f"{key}: is {device[key]!r}, needs {want!r}")
        for key, floor in self.at_least.items():
            have = _version_key(device.get(key))
            if have is None:
                failed.append(f"{key}: not reported")
            elif _older(have, _version_key(floor) or ()):
                failed.append(f"{key}: {device.get(key)} is older than {floor}")
        if self.max_age_s is not None:
            try:
                age = self._clock() - float(device.get("reported_at"))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                failed.append("reported_at: not reported")
            else:
                # NaN compares False against everything, so without this a
                # reported_at of "nan" is neither too old nor in the future.
                if not math.isfinite(age):
                    failed.append("reported_at: not a time")
                elif age > self.max_age_s:
                    failed.append(f"reported_at: {int(age)}s ago, limit {int(self.max_age_s)}s")
                elif age < -self.FUTURE_SKEW_S:
                    failed.append("reported_at: is in the future")
        device_id = str(device.get("device_id") or "")
        if failed:
            return Check(self.name, False, "; ".join(failed),
                         "This needs an up-to-date device enrolled with your organisation. "
                         "Update it, then try again.",
                         detail={"device_id": device_id,
                                 "failed": [f.split(":", 1)[0] for f in failed]})
        return Check(self.name, True, detail={"device_id": device_id})


class EgressAllowed:
    """Where this is going is on the allowlist.

    Takes any policy whose ``check(host)`` answers ``(allowed, rule)`` -- awwall's
    ``Policy`` is one. ``destination`` is a bare ASCII hostname or IPv4 address,
    optionally with a port, or a bracketed IPv6 address.

    The destination must MATCH that grammar; it is not scrubbed of bad characters.
    A blacklist of separators always misses one -- a full-width slash that
    normalises to ``/``, a percent-escape, a NUL -- and the thing that finally
    connects may read the string differently from the thing that allowed it.
    An internationalised name is presented in its ASCII (``xn--``) form.
    """

    name = "egress_allowed"
    _LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    _HOST_RE = re.compile(rf"({_LABEL}(?:\.{_LABEL})*)(?::(\d{{1,5}}))?")
    _V6_RE = re.compile(r"\[([0-9a-f:.]{2,45})\](?::(\d{1,5}))?")

    def __init__(self, policy: Any) -> None:
        self._policy = policy

    def check(self, presented: Mapping[str, Any]) -> Check:
        raw = presented.get("destination")
        if not isinstance(raw, str) or not raw:
            return Check(self.name, False, "no destination presented",
                         "Say where this is going, then try again.")
        lowered = raw.lower()   # no strip(): surrounding whitespace is not a hostname
        m = self._HOST_RE.fullmatch(lowered) or self._V6_RE.fullmatch(lowered)
        if m is None or len(m.group(1)) > 253:
            return Check(self.name, False, "destination is not a bare host",
                         "That destination is not reachable from here.")
        host = m.group(1)
        verdict = self._policy.check(host)
        allowed, rule = (verdict if isinstance(verdict, tuple) and len(verdict) == 2
                         else (False, None))
        if allowed is not True:
            return Check(self.name, False, "destination is not on this gate's allowlist",
                         "That destination is not reachable from here. Ask the owner to "
                         "allow it.")
        return Check(self.name, True, detail={"destination": host,
                                              "rule": getattr(rule, "pattern", None)})


class ContentClean:
    """What the visitor is sending may leave.

    ``inspect`` is given the whole body as bytes and answers a mapping with
    ``allowed`` (True to let it through) and optionally ``findings`` (names of
    what matched). Wire it to whatever inspects content for you.

    Content over ``max_bytes`` is REFUSED, not sampled. Inspecting the first part
    and passing the rest is how a content filter gets walked around: the secret
    goes after the cut. Nothing to send is clean.

    Only the NAMES of findings are kept. The matched text is the very thing that
    was not supposed to travel, and an audit trail is a place it would travel to.
    """

    name = "content_clean"

    def __init__(self, inspect: Callable[[bytes], Any], *,
                 max_bytes: int = 1_048_576) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self._inspect = inspect
        self.max_bytes = max_bytes

    def check(self, presented: Mapping[str, Any]) -> Check:
        content = presented.get("content")
        if content is None or len(content) == 0:
            return Check(self.name, True, detail={"bytes": 0})
        if isinstance(content, str):
            data = content.encode("utf-8")
        elif isinstance(content, (bytes, bytearray, memoryview)):
            data = bytes(content)
        else:
            return Check(self.name, False, "content is neither bytes nor text",
                         "That cannot be sent through here.")
        if len(data) > self.max_bytes:
            return Check(self.name, False,
                         f"content is {len(data)} bytes, this gate inspects at most "
                         f"{self.max_bytes}",
                         "That is too large to send through here.")
        verdict = self._inspect(data)
        if not isinstance(verdict, Mapping) or verdict.get("allowed") is not True:
            names: list[str] = []
            if isinstance(verdict, Mapping):
                names = [str(f)[:64] for f in (verdict.get("findings") or [])][:20]
            why = ("content matched: " + ", ".join(names)) if names \
                else "content was not cleared"
            return Check(self.name, False, why,
                         "This contains something that may not leave through here. "
                         "Remove it and send again.",
                         detail={"bytes": len(data), "findings": names})
        return Check(self.name, True, detail={"bytes": len(data)})
