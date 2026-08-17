# Security Exceptions

Security exceptions are temporary, explicit, and reviewed. They do not replace dependency monitoring or a supported-version upgrade.

| Advisory | Dependency | Scope | Reason | Compensating controls | Exit condition |
|---|---|---|---|---|---|
| `PYSEC-2026-2447` | `diskcache` (transitive through FastMCP) | FastMCP local caching dependency | The audit database currently reports no fixed version. | The project does not expose a cache service, does not permit untrusted daemon access, and uses campaign/policy controls before job execution. CI documents this narrow exception rather than suppressing all audit results. | Remove the exception as soon as FastMCP or `diskcache` publishes a fixed compatible version and release an updated dependency bound. |

All other advisories must fail CI. This exception must be reviewed at every dependency update and release.
