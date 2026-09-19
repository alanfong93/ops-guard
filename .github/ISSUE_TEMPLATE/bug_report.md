---
name: 🐛 Bug report
about: Report something that isn't working
title: "[Bug] "
labels: bug
type: bug
assignees: ''
---

## Describe the bug
A clear and concise description of what the bug is.

## Steps to reproduce
1. Go to '...'
2. Run '...'
3. See error

## Expected behavior
What you thought should happen.

## Screenshots / Logs
If applicable, add screenshots or console output.

## Environment (please complete the following):
- OS: [e.g. Ubuntu 22.04, Windows 11]
- Node/Python/other version: 
- Project version/commit: 

## Additional context
Anything else you think is relevant.

## Practice
How this should be fixed. Pick one and set the matching `practice:` label.

- [ ] `practice:tdd` — reproduce the bug as a failing test first, then fix it.
- [ ] `practice:characterisation` — no test seam here. Capture current behaviour from the outside (HTTP, CLI, browser) first.

⚠️ On a bug it is almost always one of those two. The steps to reproduce above
*are* the first test — if you cannot turn them into one, the bug is not pinned down yet.

## Rigour
Add the `rigour:property-based` label if this touches any of:
`auth` `token` `crypto` `payment` `refund` `migration` `delete` `concurrency`
`replay` `tenant` — or encoding/parsing, ordering, uniqueness, resource bounds.

It means example tests are not enough. Write rules that must hold for EVERY
input and let the tool generate them. `refund(100) == 100` is an example;
*the balance never goes negative, for any sequence of operations* is a property.
