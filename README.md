# awnboard

**A front gate you can put in front of anything — and hand someone the key to.**

```bash
pip install awnboard
```

```python
from awnboard import Gate, Invited, HmacSigner, GrantLedger, invite

signer = HmacSigner(SECRET)
ledger = GrantLedger("./grants.json")

token = invite(signer, gate="beta", to="sam@example.com", uses=1)   # email this

gate = Gate("beta", target="https://internal.example/app",
            requirements=[Invited("beta", signer, ledger)])

a = gate.admit({"invitation": token, "as": "sam@example.com"})
a.admitted            # True
a.message()           # what to show the visitor
a.reasons()           # what to show the operator
```

## The problem, stated exactly

Letting one specific person reach one specific thing is still either a whole
identity deployment or a link anyone who sees it can use. So everybody ships the
link — and a link has a property nobody wants: **the link IS the credential.**

Forwarding it transfers it. A screenshot is a copy. It does not know who it was
for, so nothing can tell you who used it. And revoking it means rotating
something everyone else is still using, which is why nobody does, which is why
the invitation you regret is still live.

An invitation here names its recipient:

| field | drop it and… |
|---|---|
| `gate` | it opens whichever door it is shown to |
| `to` | it is a share link again — forwarding works |
| `uses` | one solve opens the door forever |
| `exp` | the damage is unbounded in time |
| `id` | you can only revoke *everyone*, by rotating the key |

```python
gate.admit({"invitation": token, "as": "mallory@example.com"})   # refused
```

The signature is perfect. It is still refused, and the refusal does not tell
Mallory who it *was* for — a gate must not become a directory of who was invited.

## The ladder

A gate holds requirements, and **every one must be met.** There is deliberately no
"any of these" mode: an OR ladder grows a weak rung nobody removes, and before
long every visitor arrives through it while the strong rungs sit there looking
reassuring. Two gates in front of two targets is the honest way to say "these
people, or those people".

```python
Gate("beta", target=url, requirements=[
    Invited("beta", signer, ledger),                  # a grant addressed to you
    Passcode(digest, salt=salt),                      # something you were told
    KnownSubject(["u_42", "u_77"]),                   # an allowlist
    VerifiedHuman("app:mine", NEST_SECRET),           # is there a person there
])
```

Every rung is **unmet by default**. A requirement that cannot evaluate — no input,
a checker that is not installed, a ledger it cannot read — returns unmet, never
met. There is no path through this package where an error becomes admission, and
a rung that *raises* is unmet rather than a 500 somebody later wraps in a
`try/except` that admits.

`VerifiedHuman` delegates to [awnest](https://github.com/Aitherium/awnest) when it
is installed, and is **unmet — not skipped** when it is not. A gate that quietly
drops its strongest requirement because a dependency is missing is worse than one
that refuses.

## Refusals, for two audiences at once

```python
a.message()   # "That invitation was sent to someone else. Ask for your own."
a.reasons()   # "invited: invitation is addressed to someone else"
a.as_record() # a flat audit record — no tokens, no secrets
```

The visitor gets remedies: actionable, and carrying nothing that helps anyone
guess. The operator gets every rung's verdict. Both come off the same object,
because two objects drift and the one that drifts is the one nobody reads.

Every unmet rung is shown, not just the first — telling someone the code was
wrong, and then, after they fix it, that they also needed an invitation, is how a
two-step gate becomes a support ticket.

## Revocation is per grant

```python
ledger.revoke("inv-3", reason="left the project")   # just that one
ledger.history("inv-3")                             # who walked through, and when
```

That last line is the question a share link cannot answer at all.

The ledger is a JSON file on purpose: a gate in front of one thing should not
require anyone to run a service, because the moment it does, people put the gate
somewhere else. The interface is four methods — reimplement it over Redis or
Postgres when a deployment needs a real compare-and-set. Two *simultaneous*
acceptances of a one-use invitation can both land against the file version; that
is written down in the docstring rather than hidden, because the honest limit of
a small thing is more useful than a big thing nobody deploys.

An unreadable ledger **fails closed**. Read as empty it would un-revoke everything
and re-open every one-use invitation at once — the quietest possible catastrophe.

## What it composes with

| with | what it adds |
|---|---|
| a human check | is there a person there at all, at what strength |
| an identity system | who specifically, once they are through |
| an authz system | what they may do on the other side |
| an audit trail | who walked through, kept where a missing record shows |
| a tunnel or a mesh | a target with no public address, reachable through the gate |
| signing + content-addressed transfer | hand someone a sealed grant instead of a link |

None of it is a dependency. A gate with a passcode and an invitation works with
nothing else installed — that is the point of a brick.

## Command line

```
awnboard invite  --gate beta --to sam@example.com --uses 1
awnboard read    TOKEN --gate beta          verify without spending it
awnboard admit   --gate beta --invitation TOKEN --as sam@example.com
awnboard revoke  INVITATION_ID --reason "left the project"
awnboard history INVITATION_ID
awnboard hash    --code sunrise-42 --salt <salt>
awnboard --self-test
```

Exit codes: **0** admitted / ok · **1** refused or broke · **2** you asked wrongly.

The signing secret comes from `--secret` or `AWNBOARD_SECRET` and is never
defaulted: a default key is a key everybody has, and here it is the key that
issues invitations.

## Licence

Apache-2.0.
