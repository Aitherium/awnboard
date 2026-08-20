"""awnboard -- a front gate you can put in front of anything.

    from awnboard import Gate, Invited, Passcode, HmacSigner, GrantLedger, invite

    signer = HmacSigner(SECRET)
    ledger = GrantLedger("./grants.json")
    token  = invite(signer, gate="beta", to="sam@example.com", uses=1)   # email this

    gate = Gate("beta", target="https://internal.example/app",
                requirements=[Invited("beta", signer, ledger)])
    a = gate.admit({"invitation": token, "as": "sam@example.com"})
    a.admitted, a.message()

The whole idea is that an invitation NAMES its recipient, so forwarding it stops
working, and that grants are revocable one at a time, so revoking the one you
regret does not revoke everyone else's.
"""
from awnboard.gate import Admission, Gate, GateError
from awnboard.grant import (
    TOKEN_PREFIX,
    GrantLedger,
    HmacSigner,
    Invitation,
    InvitationError,
    Signer,
    invite,
    read_invitation,
)
from awnboard.requirements import (
    Check,
    Invited,
    KnownSubject,
    Passcode,
    Requirement,
    VerifiedHuman,
    hash_passcode,
)

__version__ = "0.1.0"

__all__ = [
    "Gate", "Admission", "GateError",
    "invite", "read_invitation", "Invitation", "InvitationError",
    "Signer", "HmacSigner", "GrantLedger", "TOKEN_PREFIX",
    "Check", "Requirement", "Passcode", "Invited", "KnownSubject", "VerifiedHuman",
    "hash_passcode",
    "__version__",
]
