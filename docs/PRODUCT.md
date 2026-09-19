# Who

Alan, driving an AI agent — OpenCode today, any MCP-speaking agent (OpenClaw, Hermes) tomorrow — against his self-hosted production systems.

# Must be able to

1. Ask "how do I update n8n?" and get the answer **with the runbook passage it came from** — cited, and only from verified procedures
2. Run a verified procedure unattended: "update n8n" maps to the allowlisted script, auto-executes, always logged
3. Have any **model-composed** fix stopped at the gate until Alan approves it
4. See afterwards exactly what was asked, returned, executed, and who approved it
5. Check the accuracy claim: a published retrieval score against a naive keyword baseline

# Done when

"Update n8n" in a fresh agent session returns the cited steps and executes the allowlisted script fully logged; a novel fix refuses to execute without approval; the eval harness beats the keyword baseline. Fails closed everywhere: judge down → needs-review, no retrieval → no execution path, audit write fails → refuse to execute.

# Not this project

Being an agent. Model hosting or fine-tuning. A UI. Multi-tenancy. Anything resembling a full ITSM tool.
