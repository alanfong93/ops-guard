---
name: 🚀 Feature request
about: Suggest a new idea or improvement
title: "[Feature] "
labels: enhancement
type: feature
assignees: ''
---

## Is your feature request related to a problem?
Explain the problem you're trying to solve.

## Describe the solution you'd like
What should happen if this existed?

## Describe alternatives you've considered
Other workarounds or ideas you've thought of.

## Additional context
Anything else (mockups, screenshots, references).

## Done when
One line. A human-checkable statement of success.

> Done when a picker finishes a consignment on the phone, alone.

⚠️ If you cannot write this line, the requirement is not settled. Do not open the
issue yet — an agent will only guess at what you left out.

## Practice
How this should be built. Pick one and set the matching `practice:` label.

- [ ] `practice:tdd` — you know what correct looks like. Write the failing test first.
- [ ] `practice:spec-first` — something outside depends on the shape (HTTP endpoint, published signature, event payload, DB schema, plugin seam). Agree the contract first.
- [ ] `practice:prototype` — correct is not known yet. Build to learn, throw it away, then decide again.
- [ ] `practice:characterisation` — the feature lands in code with no test seam. Capture current behaviour first.

## Rigour
Add the `rigour:property-based` label if this touches any of:
`auth` `token` `crypto` `payment` `refund` `migration` `delete` `concurrency`
`replay` `tenant` — or encoding/parsing, ordering, uniqueness, resource bounds.

It means example tests are not enough. Write rules that must hold for EVERY
input and let the tool generate them. `refund(100) == 100` is an example;
*the balance never goes negative, for any sequence of operations* is a property.
