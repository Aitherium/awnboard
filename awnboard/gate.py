"""The gate: a target, a ladder, and one answer.

    gate = Gate("beta", target="https://internal.example/app",
                requirements=[Invited("beta", signer, ledger), Passcode(digest, salt=s)])
    admission = gate.admit({"invitation": tok, "as": "sam@example.com", "passcode": "..."})
    if admission.admitted:
        redirect(admission.target)

WHAT A GATE IS FOR
==================
Putting one specific person in front of one specific thing, without deploying an
identity system and without emailing a link that anyone who sees it can use.

The ladder is ALL of it, not any of it
======================================
Every requirement must be met. There is no "any of these" mode, and that omission
is deliberate: an OR ladder is the shape that grows a weak rung nobody removes,
and after a while every visitor is arriving through it while the strong rungs sit
there looking reassuring. Two gates in front of two targets is the honest way to
say "these people, or those people".

REFUSAL IS SPECIFIC AND SAFE AT THE SAME TIME
=============================================
`Admission` carries every rung's verdict, so an operator can see exactly which one
stopped a visitor. What the VISITOR is shown is the `remedy` -- actionable, and
carrying nothing that helps someone guess. Both audiences are served by the same
object because two objects drift, and the one that drifts is the one nobody reads.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from awnboard.requirements import Check, Requirement

__all__ = ["Gate", "Admission", "GateError"]


class GateError(RuntimeError):
    """The gate cannot be built or cannot answer. Never raised for a refusal --
    a refusal is an ordinary answer and comes back as an Admission."""


@dataclass(frozen=True)
class Admission:
    """The answer, for both audiences: the operator and the visitor."""

    gate: str
    admitted: bool
    checks: tuple[Check, ...] = ()
    target: Optional[str] = None
    at: float = field(default_factory=time.time)
    subject: str = ""

    @property
    def failed(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if not c.met)

    def message(self) -> str:
        """What to show the VISITOR. Remedies only -- never the internal reason.

        Every unmet rung is shown, not just the first: telling somebody the code was
        wrong, then after they fix it telling them they also need an invitation, is
        how a two-step gate becomes a support ticket.
        """
        if self.admitted:
            return "Welcome in."
        remedies = [c.remedy for c in self.failed if c.remedy]
        if not remedies:
            return "This gate is closed to you right now."
        # Deduplicated, order preserved: two rungs often want the same next step.
        seen, out = set(), []
        for r in remedies:
            if r not in seen:
                seen.add(r)
                out.append(r)
        return " ".join(out)

    def reasons(self) -> str:
        """What to show the OPERATOR, or write to an audit trail."""
        return "; ".join(f"{c.name}: {c.why or ('met' if c.met else 'unmet')}"
                         for c in self.checks)

    def as_record(self) -> dict[str, Any]:
        """A flat record for an audit trail. Contains no secrets and no tokens."""
        return {
            "gate": self.gate, "admitted": self.admitted, "at": self.at,
            "subject": self.subject,
            "checks": [{"name": c.name, "met": c.met, "why": c.why} for c in self.checks],
        }


class Gate:
    """One door in front of one thing."""

    def __init__(self, gate_id: str, *, target: Optional[str] = None,
                 requirements: Sequence[Requirement] = (), note: str = "") -> None:
        if not gate_id:
            raise GateError("a gate needs an id -- invitations name it, and one that "
                            "names nothing can be presented at any gate")
        if not requirements:
            # An empty ladder is a door standing open, and it is nearly always a
            # half-finished configuration rather than an intention. Say so at
            # construction, where somebody is looking, rather than at admission,
            # where nobody is.
            raise GateError(
                f"gate {gate_id!r} has no requirements -- that is not a gate. Add at "
                "least one (a passcode is the floor), or serve the target directly "
                "and be honest that it is open."
            )
        self.id = gate_id
        self.target = target
        self.requirements = tuple(requirements)
        self.note = note

    def admit(self, presented: Mapping[str, Any]) -> Admission:
        """Run every rung. Returns an Admission; raises only on a broken gate."""
        checks: list[Check] = []
        for req in self.requirements:
            try:
                c = req.check(presented)
            except Exception as exc:
                # A rung that THROWS is unmet. Letting the exception escape would
                # hand the caller a 500, and the tempting fix for a 500 on a login
                # path is a try/except that admits.
                c = Check(getattr(req, "name", req.__class__.__name__), False,
                          f"requirement raised: {exc}",
                          "This gate cannot check you right now. Try again shortly.")
            checks.append(c)
        ok = bool(checks) and all(c.met for c in checks)
        subject = str(presented.get("subject") or presented.get("as") or "")
        return Admission(self.id, ok, tuple(checks),
                         target=self.target if ok else None, subject=subject)

    def describe(self) -> dict[str, Any]:
        """What this gate asks for, safe to show a visitor BEFORE they try.

        Telling people what a gate wants is not a leak and saves the round trip
        where they discover it one rung at a time.
        """
        return {"gate": self.id, "note": self.note,
                "requires": [getattr(r, "name", r.__class__.__name__)
                             for r in self.requirements]}
