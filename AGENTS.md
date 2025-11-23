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

## Commit Guidelines
- Keep each commit a small, meaningful chunk of work. Avoid mixing unrelated edits—do not add a new helper while also fixing unrelated whitespace in the same commit.
- Ensure every commit builds or passes the relevant basic checks on its own. A clean, compiling state at each step makes reviews faster and keeps `git bisect` and reverts safe.
- Prefer one logical change per commit (e.g., “add feature X”, “refactor Y”, “fix bug Z”, or “format module A”) rather than a mixture. If formatting is needed, run clang-format or similar in a dedicated formatting-only commit.
- Write descriptive, imperative commit subjects (e.g., “Add health check for agent foo” instead of “fixed stuff”), and reference issues or design documents when helpful. Long changes should be split into a short series of self-contained commits that each compile and stand alone in the history.
- Avoid committing temporary debug prints or experimental tweaks. If they must land for remote debugging, clearly mark them and remove them in a follow-up commit.
- These practices keep the history clear, speed up code ownership decisions, simplify reviews, and make automated tools like `git bisect` more reliable.

### Working with igt-gpu-tools
- `igt-gpu-tools` is used for GPU testing and debugging in this project. Apply the same small, compiling, single-purpose commit philosophy even during exploratory work.
- Begin GPU test efforts with a commit that documents the test setup or commands used to run specific `igt` cases, so others can reproduce your environment.
- Use separate commits for distinct activities: adding new `igt-gpu-tools` dependencies or configuration; adding wrappers or helpers around `igt` tests; fixing or adjusting existing tests based on `igt` results.
- When exploring or debugging, keep experiment commits small and summarized. Note which `igt` command(s) you ran (include example CLI invocations), what behavior or regression you investigated, and any new logs, traces, or artifacts produced (and where they live).
- Capture new knowledge as you go: add short “How to reproduce” or “How to run this test” snippets to docs when introducing or using new `igt` cases, and link to any internal runbooks or scripts that drive `igt-gpu-tools`.
