# Docs (humans + agents)

Update docs in the same commit as the behaviour change. Mermaid only. No empty scaffolds.

Required when they apply:

- `docs/PRODUCT.md` — who it is for, what they must be able to do, done when, not this project
- `docs/architecture.md` — what changed (C4 Context for a material external/system boundary; C4 Container for 2+ independently runnable/deployable units that materially affect delivery or operation; ER if persisted; sequence if 2+ services talk)
- `docs/system_flow.md` — the workflow, as a mermaid flowchart
- `docs/API_Reference.md` and/or `docs/API_OpenAPI.json` — every endpoint add/change/remove
- `docs/adr/NNNN-slug.md` — why, if we rejected a real alternative
- `CONTEXT.md` — new business term, plus the alias we will not use

Required only if an entity has >3 states with illegal transitions: a state diagram in `docs/architecture.md`.

Component diagrams are exceptional: use them only after recurring navigation or change mistakes show that the code and other diagrams do not explain an internal boundary. Never generate C4 Code, class, use case, or DFD diagrams by default.

GitHub issues may discuss a decision. The durable copy is the ADR in this repo.
