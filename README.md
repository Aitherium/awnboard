# awnboard

<!-- aither-header:start GENERATED from the ecosystem registry. Edits here are overwritten; change the registry instead. -->

**[Docs](https://aitherium.github.io/awnboard/)**  ·  [Source](https://github.com/Aitherium/awnboard)  ·  `pip install awnboard`  ·  [The Aither World](https://aitherium.github.io/)

> **The Aither World** is an operating system for agents — a Linux you can hand to one, the runtimes it works in, and the tools it works with. [awnix](https://github.com/Aitherium/awnix) is the Linux underneath it; **awnboard** is one of its 36 bricks — each installs on its own, runs offline, and needs no account.
>
> **Start here:** Put a gate in front of one URL and let exactly one person through it with a code you sent them.

<!-- aither-header:end -->

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

<!-- aither-ecosystem:start GENERATED from the ecosystem registry. Edits here are overwritten; change the registry instead. -->

## The aw family

Standalone tools that share one idea: **replace something you would otherwise have to _trust_ with something you can _check_.**

Each installs on its own, works offline, and needs no account.

| | instead of trusting | you check |
|---|---|---|
| [awdk](https://github.com/Aitherium/awdk) | a framework's idea of how your agents should run | one loop you can read, pointed at a backend you already pay for |
| [awskills](https://github.com/Aitherium/awskills) | that an agent knows your procedure | the procedure written down, versioned, and loadable by any agent |
| [awm](https://github.com/Aitherium/awm) | that memory stayed in its lane | tenant:user:project scopes, so a write cannot cross a boundary |
| [awnode](https://github.com/Aitherium/awnode) | a vendor's cloud with every prompt | a local gateway routing to backends you chose |
| [awgraph](https://github.com/Aitherium/awgraph) | that grep found everything | an AST + tree-sitter call graph an agent can traverse |
| [awgit](https://github.com/Aitherium/awgit) | that no one else is editing this file | a lease, refused at commit time if you do not hold it |
| [awtoll](https://github.com/Aitherium/awtoll) | that your tooling is saving you context | the measured token cost of each tool call, and what the alternative cost |
| [awseal](https://github.com/Aitherium/awseal) | that the artifact came from who you think | an Ed25519 seal — the key that verifies is not the key that forges |
| [awshare](https://github.com/Aitherium/awshare) | that the download is intact | content-addressed bundles, verified on fetch |
| [awnest](https://github.com/Aitherium/awnest) | that there is a person on the other end | a verdict with evidence, where "we could not tell" is not "yes" |
| **awnboard** _(you are here)_ | a share link anyone who sees it can use | an invitation addressed to one person, for one gate, revocable |
| [awnix](https://github.com/Aitherium/awnix) | that the box is what you left it as | an immutable image you built, with atomic rollback |
| [awrecover](https://github.com/Aitherium/awrecover) | that the restore worked | a restore that fully lands or does not land at all |
| [awrelay](https://github.com/Aitherium/awrelay) | a SaaS in the middle of your agents | findings, alerts and coordination over your own transport |
| [awmail](https://github.com/Aitherium/awmail) | a mailbox somebody else can read | mail your agents send and receive over your own server |
| [awfind](https://github.com/Aitherium/awfind) | one vendor's idea of the web | results from whichever providers you configured |
| [awbrowse](https://github.com/Aitherium/awbrowse) | that the page said what you were told | the render, the DOM and the requests it made |
| [gobbonet-agentic](https://github.com/Aitherium/gobbonet-agentic) | the model to keep a 300-message campaign coherent by itself | campaign facts recalled from scoped memory you can list and edit |
| [aitherkvcache](https://github.com/Aitherium/aitherkvcache) | a vendor's quantisation defaults | sub-byte KV cache kernels you can benchmark yourself |
| [AitherZero](https://github.com/Aitherium/AitherZero) | a pile of scripts nobody has numbered | numbered, discoverable automation with declarative playbooks |
| [AitherConnect](https://github.com/Aitherium/AitherConnect) | what a page tells your browser to do | a federated search and desktop bridge you host |
| [awreason](https://github.com/Aitherium/awreason) | a confident paragraph | the phases it went through, and every tool call it made to get there |
| [awrecurse](https://github.com/Aitherium/awrecurse) | that everything you pasted in was actually read | which slices it opened, and what it concluded from each |
| [awprism](https://github.com/Aitherium/awprism) | the first explanation that fits | the ranked alternatives, and the observation that separates them |
| [awrepl](https://github.com/Aitherium/awrepl) | what the agent believes the value is | the value, printed from the live session |
| [awresearch](https://github.com/Aitherium/awresearch) | a summary of pages nobody opened | every claim against the source it came from |
| [awpredict](https://github.com/Aitherium/awpredict) | a model because it trained without erroring | its prediction against a self-updating lookup, on the rows that are actually novel |
| [awsh](https://github.com/Aitherium/awsh) | that you already know the name of the command | what it decided your line meant, before it acts on it |
| [awkno](https://github.com/Aitherium/awkno) | that the docs site is up, or that you remember the family | the whole ecosystem in your terminal, with no network at all |

[**awnix**](https://github.com/Aitherium/awnix) is the ground floor — A Linux you can hand to an agent — immutable base, capabilities included.

## The Aitherium ecosystem

Every repository here is public. Each publishes an `aither-manifest.json` beside its page, so any surface can read every sibling's — the network is browsable from any node in it.

| repo | what it is | pages |
|---|---|---|
| [awdk](https://github.com/Aitherium/awdk) | Build AI agent fleets — 3 lines, any backend, local or cloud | [docs](https://aitherium.github.io/awdk/) |
| [awskills](https://github.com/Aitherium/awskills) | Portable agent skills — self-contained procedures an agent loads on demand | [docs](https://aitherium.github.io/awskills/) |
| [awm](https://github.com/Aitherium/awm) | A portable, scoped agent memory | [docs](https://aitherium.github.io/awm/) |
| [awnode](https://github.com/Aitherium/awnode) | A lightweight local gateway — bridges your apps to the AI backends you chose | [docs](https://aitherium.github.io/awnode/) |
| [awrun](https://github.com/Aitherium/awrun) | A priority-aware queue and dispatcher for agentic runs and ad-hoc CI builds. It also judges whether the runner pool is big enough for the queue it is draining, and can ask a host to grow it -- reserving capacity is zero-sum, so a saturated pool needs more of it, not a different share of it | [docs](https://aitherium.github.io/awrun/) |
| [awgraph](https://github.com/Aitherium/awgraph) | A semantic code graph for agents — AST + tree-sitter, call graphs | [docs](https://aitherium.github.io/awgraph/) |
| [awgit](https://github.com/Aitherium/awgit) | Semantic version control on top of git — edit-ops and leases | [docs](https://aitherium.github.io/awgit/) |
| [awtoll](https://github.com/Aitherium/awtoll) | What every tool call costs you in context, measured from your own transcripts | [docs](https://aitherium.github.io/awtoll/) |
| [awseal](https://github.com/Aitherium/awseal) | Sign an artifact so a stranger can verify it | [docs](https://aitherium.github.io/awseal/) |
| [awshare](https://github.com/Aitherium/awshare) | Publish an artifact and fetch it back verified | [docs](https://aitherium.github.io/awshare/) |
| [awdit](https://github.com/Aitherium/awdit) | An append-only audit trail whose gaps are DETECTABLE | [docs](https://aitherium.github.io/awdit/) |
| [awbac](https://github.com/Aitherium/awbac) | Role-based access control that fails closed and explains itself | [docs](https://aitherium.github.io/awbac/) |
| [awiam](https://github.com/Aitherium/awiam) | Who is this caller? A directory and session store that fails honestly | [docs](https://aitherium.github.io/awiam/) |
| [awtunnel](https://github.com/Aitherium/awtunnel) | Reach a service that has no public address | [docs](https://aitherium.github.io/awtunnel/) |
| [awnest](https://github.com/Aitherium/awnest) | Prove there is a human before you let them into the nest | [docs](https://aitherium.github.io/awnest/) |
| **awnboard** _(you are here)_ | A front gate you can put in front of anything, and hand someone the key to | [docs](https://aitherium.github.io/awnboard/) |
| [awnix](https://github.com/Aitherium/awnix) | A Linux you can hand to an agent — immutable base, capabilities included | [docs](https://aitherium.github.io/awnix/) |
| [awrecover](https://github.com/Aitherium/awrecover) | Labelled snapshots with an all-or-nothing restore | [docs](https://aitherium.github.io/awrecover/) |
| [awrelay](https://github.com/Aitherium/awrelay) | Portable agent messaging — findings, alerts, coordination | [docs](https://aitherium.github.io/awrelay/) |
| [awmail](https://github.com/Aitherium/awmail) | Give an agent an email address — send, and actually receive | [docs](https://aitherium.github.io/awmail/) |
| [awnet](https://github.com/Aitherium/awnet) | The agentic web — agents host a mesh, and agents join one | [docs](https://aitherium.github.io/awnet/) |
| [awfind](https://github.com/Aitherium/awfind) | A portable search client — query, results, ranking | [docs](https://aitherium.github.io/awfind/) |
| [awbrowse](https://github.com/Aitherium/awbrowse) | A portable browser client — navigate, console, network, DOM, screenshot | [docs](https://aitherium.github.io/awbrowse/) |
| [awknowledge](https://github.com/Aitherium/awknowledge) | How to run a coding agent so the result survives — the laws, with evidence | [docs](https://aitherium.github.io/awknowledge/) |
| [gobbonet-agentic](https://github.com/Aitherium/gobbonet-agentic) | GobboNet campaigns with a real agent brain — scoped memory, graph recall | — |
| [aitherkvcache](https://github.com/Aitherium/aitherkvcache) | Near-optimal KV cache quantization for LLM inference — sub-byte compression | [docs](https://aitherium.github.io/aitherkvcache/) |
| [AitherZero](https://github.com/Aitherium/AitherZero) | PowerShell 7+ automation framework — numbered, self-describing scripts | [docs](https://aitherium.github.io/AitherZero/) |
| [AitherConnect](https://github.com/Aitherium/AitherConnect) | Browser extension — federated AI search, page context, and the Living OS overlay | [docs](https://aitherium.github.io/AitherConnect/) |
| [awreason](https://github.com/Aitherium/awreason) | A portable reasoning client — sessions, phases, thoughts, and the chain that produced the answer | [docs](https://aitherium.github.io/awreason/) |
| [awrecurse](https://github.com/Aitherium/awrecurse) | Answer a question over a context far larger than the window — recursively, with the trace kept | [docs](https://aitherium.github.io/awrecurse/) |
| [awprism](https://github.com/Aitherium/awprism) | Turn a failure into ranked hypotheses — and say what would confirm each one | [docs](https://aitherium.github.io/awprism/) |
| [awrepl](https://github.com/Aitherium/awrepl) | A REPL an agent can actually use — state that survives between turns | [docs](https://aitherium.github.io/awrepl/) |
| [awresearch](https://github.com/Aitherium/awresearch) | Ask a research question, get a cited report you can check | [docs](https://aitherium.github.io/awresearch/) |
| [awpredict](https://github.com/Aitherium/awpredict) | Predict what your environment does next, and how surprised you were | [docs](https://aitherium.github.io/awpredict/) |
| [awsh](https://github.com/Aitherium/awsh) | Your terminal answers you -- type a question where a command would go | — |
| [awkno](https://github.com/Aitherium/awkno) | The man page for the Aither World — every brick, stack and law, offline | [docs](https://aitherium.github.io/awkno/) |

<div id="aither-constellation" data-self="awnboard"></div>
<script src="aither-constellation.js"></script>

<!-- aither-ecosystem:end -->
