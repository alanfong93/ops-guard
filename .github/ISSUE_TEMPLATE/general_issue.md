---
name: General Issue
about: Use this for anything that doesn't fit bug or feature request
title: '[ISSUE] '
labels: ''
assignees: ''
---

## Description
A clear and concise description of the issue.

## Steps to Reproduce (if applicable)
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Expected Behavior (if applicable)
What you expected to happen.

## Actual Behavior (if applicable)
What actually happened.

## Additional Details (Screenshots/Logs)
Add any other context, screenshots, logs, or information that might be helpful.

## Practice
How this should be built. Pick one and set the matching `practice:` label.

- [ ] `practice:tdd` — behaviour is known. Write the failing test first, then the code.
- [ ] `practice:spec-first` — something outside depends on the shape. Agree the contract first.
- [ ] `practice:characterisation` — no test seam. Capture current behaviour first, then change it.
- [ ] `practice:refactor` — behaviour unchanged. Freeze the existing tests, move the code.
- [ ] `practice:prototype` — correct is not known yet. Build to learn, throw it away, decide again.

⚠️ If you cannot pick one, the design is not settled. Do not open the issue yet.

## Rigour
Add the `rigour:property-based` label if this touches any of:
`auth` `token` `crypto` `payment` `refund` `migration` `delete` `concurrency`
`replay` `tenant` — or encoding/parsing, ordering, uniqueness, resource bounds.

It means example tests are not enough. Write rules that must hold for EVERY
input and let the tool generate them. `refund(100) == 100` is an example;
*the balance never goes negative, for any sequence of operations* is a property.
