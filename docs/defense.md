# Interview Defense Pack. AD-Audit-Toolkit

This is my preparation for defending this project in an interview. It is written the way I would explain the tool at a whiteboard.

## Two-minute pitch

I run Active Directory as a sysadmin. I know how it drifts. Accounts go stale, service accounts pile up non-expiring passwords, and privileged groups grow over time. I built a PowerShell module that audits that drift the way an attacker would look at it. It runs ten checks. Stale accounts, weak password settings, privileged group sprawl, inactive admins, kerberoastable accounts, unconstrained delegation, dormant computers, and the domain password policy. It produces a scored HTML report I can hand to a manager. It is read-only, so it is safe to run in production. It also ships with a synthetic demo domain, so anyone can run it in seconds without a lab. I built it because the first thing an attacker does after getting in is enumerate exactly these weaknesses. I want to see them first.

## Architecture walkthrough

There are two data sources. A live collector that reads a real domain through the RSAT ActiveDirectory module, and a demo loader that reads a bundled synthetic dataset. Both return the exact same object shape. Users, computers, privileged groups, and the password policy.

Every check is a function that takes that normalized data and returns findings. A finding has a check id, a severity, the object name, its type, and a plain detail string. The checks never touch Active Directory. They only read the normalized objects. That separation is the core design decision. It means the checks do not care where the data came from.

The findings roll up into a summary with counts by severity and a hygiene score. A report writer turns the check results into a self-contained HTML file. No external assets, so it opens anywhere.

## Key decisions and tradeoffs

**One normalized object shape for both sources.** I decided early that live mode and demo mode would produce identical objects. This made every check a pure function over data. It made testing trivial. The tradeoff is that the demo loader and the live collector both have to be kept in sync by hand. I accept that because the shape is small.

**Read-only by design.** The module has no code that writes to the directory. This was a deliberate constraint. An audit tool that can also change things is a tool people are afraid to run. I would rather output recommendations and let a human act on them.

**A per-category maturity score, not a raw count.** My first score subtracted a fixed penalty per finding. A messy domain floored the score at zero. That is useless feedback. I changed it so each of the ten categories is worth ten points and loses points based on the severity of its worst finding. The score now moves in a readable range and reflects breadth of coverage, not volume of noise.

**Recursive group resolution.** Privileged membership has to follow nested groups, because that is how privilege actually accumulates. I resolve membership with a queue that walks nested groups and de-duplicates. A check that only read direct membership would miss the real risk.

## Known limitations

- Live mode needs the RSAT ActiveDirectory module and read rights in the domain.
- It reads the default domain password policy. It does not yet read fine-grained password policies, so shops that use PSOs get a partial policy view.
- LastLogonDate is not perfectly replicated across domain controllers, so a stale finding should be confirmed before action. I treat findings as leads, not verdicts.
- It audits one domain at a time.

## How would you extend this to enterprise scale

I would run it as a scheduled job against each domain and write the findings to a central store instead of a local HTML file. Findings go to a database or a log pipeline keyed by object and check. Then two things become possible. First, trend tracking, so I can show whether hygiene is improving. Second, drift alerts, so a new kerberoastable admin or a new unconstrained delegation raises an alert the day it appears instead of at the next manual audit. I would add CSV and JSON export first, because that is what makes the tool a data source rather than a one-off report. For very large directories I would page the collection and avoid loading every object into memory at once.

## Security concepts this project demonstrates

- **Identity as an attack surface.** Every check maps to something an attacker does. I can explain why each finding matters in attacker terms, not just as a policy violation.
- **Kerberoasting.** Any domain user can request the service ticket of an account that has a service principal name, then crack it offline. That is why SPNs on privileged users are a real risk and why long random passwords or group managed service accounts are the fix.
- **Unconstrained delegation.** An object trusted for unconstrained delegation caches the TGT of anyone who authenticates to it. Compromise it and you can impersonate those users. Domain controllers hold this by design, so the check excludes them.
- **Standing privilege.** Sprawl and inactive admins are risk because they are credentials nobody is watching. The fix is least privilege and just-in-time elevation.
- **Password economics.** Non-expiring passwords, blank-password flags, and weak policy all lower the cost of guessing or reusing a credential.

## Likely interview questions with model answers

**1. Why PowerShell.** It is the native language for Active Directory administration. The audience for this tool already runs PowerShell. It has first-class access to the directory through the ActiveDirectory module. Writing it in anything else would add friction for no benefit.

**2. How do you test something that needs a domain.** I do not test against a domain. The checks are pure functions over normalized data. I feed them a small handmade dataset in memory and assert on the findings. The demo dataset exercises the same code path a real domain would. So the tests are fast and run anywhere, including CI.

**3. Is it safe to run in production.** Yes. It is read-only. There is no code in the module that writes to the directory. It reads users, computers, groups, and the password policy, and it produces a report. Running it changes nothing.

**4. How does the kerberoasting check work.** It finds enabled user accounts that carry a service principal name. Those accounts can have their service ticket requested by any domain user and cracked offline. The check scores privileged accounts higher because a cracked privileged service account is worse.

**5. Why exclude domain controllers from the delegation check.** Domain controllers are trusted for delegation by design. Flagging them would be noise. The risk is any other object that holds unconstrained delegation, so the check reports users and non-DC computers only.

**6. How is the hygiene score calculated.** Each of the ten categories is worth ten points. A category loses points based on the severity of its worst finding. High costs the whole category, medium costs most of it, low costs a little. This gives a maturity view across categories instead of a raw count that one noisy check could dominate.

**7. What is a false positive risk here.** LastLogonDate is not replicated in real time across domain controllers. An account can look stale on one DC and active on another. So I treat stale findings as leads to confirm, not as verdicts. In an enterprise version I would collect from all DCs and take the most recent value.

**8. How would you reduce privileged group sprawl in practice.** Move standing membership to just-in-time elevation with an approval step. Review membership on a schedule. Remove disabled and inactive members immediately, which this tool flags directly.

**9. Why HTML output instead of a dashboard.** The report has to be portable and easy to hand to a manager. A self-contained HTML file opens anywhere with no server. When the tool moves to enterprise scale I would send findings to a central store and build a dashboard on top of that.

**10. What was the hardest part.** Getting the two data sources to produce identical objects. Once that held, every check became simple. The second hardest was the score. I had to change it from a raw penalty to a per-category maturity model to make it honest.

**11. What would you add next.** CSV and JSON export, so the tool becomes a data source. Then a comparison mode that diffs two audits and reports what drifted. Drift is the thing an attacker creates and the thing a defender wants to catch.

**12. How does this connect to your other work.** This is the identity layer. The next projects build on it. Detection tooling that watches for these weaknesses being exploited, and eventually a lab where I run the attacks and confirm the detections fire.
