# AGENTS Instructions

These instructions apply to the entire repository unless a more specific `AGENTS.md` is added deeper in the tree.

## Coding style
- Follow the Linux kernel coding style referenced in `CONTRIBUTING.md` for all C code and headers: https://www.kernel.org/doc/html/latest/process/coding-style.html
- Prefer using existing IGT helpers and macros (e.g., `igt_assert`, `igt_require`, `igt_skip`, `igt_info`, `igt_debug`) instead of reimplementing logic.
- Use `igt_describe()` for new tests to capture intent rather than a literal translation of the code.
- For new library functions, consider providing helper variants without `igt_assert/igt_require/igt_skip` when those macros are used.
- Keep runner logic independent of library helpers unless an exception already exists.

## Test and API expectations
- Tests must fall back to older kernel interfaces when newer ones are unavailable to allow use across kernel versions.
- When interacting with tools, prefer graceful exits with `printf`/`fprintf` on abnormal conditions rather than assertions.

## Commit message guidelines
- Use a component-prefixed subject following the existing history, e.g., `tests/intel/kms_joiner: short description`.
- Keep the subject concise and in the imperative mood; limit to around 72 characters.
- Separate the subject from the body with a blank line when a body is needed.
- In bodies, explain the motivation and summarize key changes; wrap text at ~72 characters.

## Patch submission reminders
- Ensure patches adhere to the Developer Certificate of Origin.
- Run relevant checks (e.g., `checkpatch.pl`) when modifying kernel-style code, tolerating expected long-line exceptions where necessary.
- Reply to CI failures and document known issues when sending patches upstream.

## Notes for Codex models
- Observe these instructions for any files changed within this repository unless superseded by a nested `AGENTS.md`.
- Do not introduce try/catch blocks around imports.
- Favor minimal diffs that align with existing code patterns and naming conventions.
