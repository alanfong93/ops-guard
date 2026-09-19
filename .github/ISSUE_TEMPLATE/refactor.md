---
name: ♻️ Refactor
about: Change the structure without changing the behaviour
title: "[Refactor] "
labels: refactor
type: refactor
assignees: ''
---

## What moves
Which code, and where it goes.

## Why
What is hard today because of the current structure. Name the concrete pain,
not "it would be cleaner".

## Behaviour that must NOT change
The whole point of a refactor is that this list stays true.

## Existing tests that cover it
List them. These are the safety net.

⚠️ **If there are no tests covering this code, it is not a refactor yet.**
Use `practice:characterisation` — capture the current behaviour first, then move
the code. Refactoring untested code is the change most likely to break it.

## Not this issue
What stays as-is. A refactor that grows scope stops being reviewable.

## Practice
How this should be built. Pick one and set the matching `practice:` label.

- [ ] `practice:refactor` — tests exist and cover it. Freeze them, move the code, same tests pass unchanged.
- [ ] `practice:characterisation` — no test seam. Capture current behaviour first, then move the code.

⚠️ On this template it is one of those two. If you reach for `practice:tdd`,
behaviour is changing — so it is not a refactor. Open a bug or feature instead.

**A test edited during a refactor is tamper, not tidying.** The tests are the only
evidence the behaviour survived. Changing them destroys the evidence.
