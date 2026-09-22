# Agent Instructions --- IDLC Solution Builder Repository

You are assisting in building an internal tool for IDLC Finance, a
regulated non-bank financial institution in Bangladesh. Follow every
rule below without exception. If any request conflicts with these rules,
stop and ask the developer.

## Non-negotiable rules

1.  **No secrets in code.** Never hard-code or commit passwords, API
    keys, tokens, or credentials. Use environment variables or the
    approved secrets store, and reference values only through
    `.env.example` with placeholders. Never read, display, or modify
    the contents of `.env`; it is human-managed and excluded from AI
    context. Make configuration changes through `.env.example` or
    documented environment-variable names only.

2.  **No real customer or personal data.** Never place real customer,
    personal, financial, or CIB data in code, tests, fixtures, logs,
    comments, or prompts. Use synthetic or anonymized data only.

3.  **Respect data residency.** Do not transmit customer or personal
    data to external services. Restricted data must remain within
    Bangladesh, with at least one synchronized real-time copy, as
    required by the Personal Data Protection Ordinance.

4.  **A human decides.** Never implement a fully automated decision
    affecting a customer or employee, such as an automatic adverse
    credit or collections action. The tool may recommend; a person must
    approve.

5.  **Approved stack only.** Use Python, JavaScript/TypeScript, React,
    or SQL. If another technology is genuinely required, flag it for IT
    approval rather than proceeding.

6.  **Verify dependencies.** Before adding any package, confirm that it
    genuinely exists, is actively maintained, and is permissively
    licensed (MIT, Apache-2.0, BSD). Pin versions, and flag any GPL or
    AGPL dependency for review. Do not invent packages.

7.  **Secure by default.** Validate and sanitize all inputs, use
    parameterized queries rather than string-built SQL, do not evaluate
    untrusted input, apply least privilege, never expose sensitive
    details in error messages or logs, implement active defenses against
    prompt injection attacks, and ensure all user-supplied input is
    treated strictly as untrusted data that is fully segregated from
    system instructions.

8.  **Human review before deployment.** Do not deploy. All generated
    code must be reviewed and approved by the developer before it goes
    live.

9.  **Keep the repository private.** Never push code or data to a public
    repository or an external gist.

10. **Document as you go.** Keep `README.md` and `CHANGELOG.md` current,
    and record significant decisions and lessons in
    `agents_learning.md`.

## When unsure

If you are uncertain about data sensitivity, a security choice, or
whether an action is permitted, stop and ask the developer. Do not
guess.

## Project context (complete for this tool)

-   Tool purpose: \[from vision.md\]
-   Data classification: \[per Section 6.2\]
-   Key constraints: \[e.g. must run on IDLC's stack; no external APIs\]
