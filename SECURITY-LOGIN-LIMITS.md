# Login attempt limits

A MongoDB collection holds a fixed 15-minute budget shared by all workers:
10 attempts per normalized account and 100 per socket peer IP. The counters use
atomic increments and an immutable _id per window; a concurrent initial insert
is retried without resetting the count. Every attempt counts, whether or not the
account exists and whether its password is correct. Limits survive new cookies
and process restarts. Blocked requests receive 429 and Retry-After before a
password hash is checked; unavailable counter storage fails closed with 503.

The collection stores HMAC digests, not plaintext account names/IPs or passwords.
The signing key is the existing application secret and is not logged. Digests
are pseudonymous data, not anonymous data. Expired counter rows are deleted
from this dedicated collection during subsequent sign-in attempts; no existing
account, appointment, medical-record or user-file rows are changed.

No indexes, real counters, hosting rules or production keys are changed by this
source PR. _id already has a built-in unique index. Before an eventual approved
release, benchmark real MongoDB concurrency and consider an expires_at TTL index
in an isolated staging database; review that index separately before production.
The existing test suite uses an in-memory MongoDB substitute, which cannot prove
production database behavior or throughput.

Reverse proxies/NAT can share a socket IP, so verify the actual deployment's
trusted proxy chain and suitability of the 100-attempt budget on staging. The
application deliberately ignores X-Forwarded-For; do not enable unrestricted
ProxyFix or accept client-supplied forwarding headers to evade this budget.
Fixed windows allow a burst across a window boundary. Targeted account blocking,
distributed botnets, credential stuffing, MFA and upstream request limits remain
operational concerns. This change limits login attempts, not all application
traffic. It neither configures nor substitutes for hosting/edge protection.

New registrations also use a deterministic, namespaced document _id for each
normalized username. MongoDB's built-in unique _id index rejects concurrent
inserts for the same new username. A losing registration receives 409 before
a session is issued, preventing it from acquiring another user's task identity.
Existing account IDs/passwords are neither read in production nor migrated.
Duplicate legacy username rows, if any, still need an authorized data review.
