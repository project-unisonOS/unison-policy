# unison-policy

The policy service is the safety and consent gate for the Unison system.

Mission:
- Decide whether an action is allowed.
- Capture evidence of user consent.
- Record an auditable log of high-impact actions.

Examples of high-impact actions:
- Send a message to a contact.
- Share current location.
- Spend money or approve payment.
- Trigger an emergency workflow / call for help.

Contract (future):
- `/evaluate` POST. Input: capability + context. Output: allow/deny + reason + required confirmation state.
- `/audit` POST. Log that an allowed action was executed (who, what, when, why).

Current state:
- Minimal HTTP service with `/health` and `/ready`.
- Containerized for inclusion in `unison-devstack`.
