# Declarative service recipes

`pagnet recipe apply manifest.yaml --network <network>` creates an offline service
participant, its exact requested network permissions, capability descriptors and
subscriptions in one transaction. It requires account authority and network
administration. It does not launch a runtime or advertise a connected endpoint.

```yaml
apiVersion: pagnet.dev/v1
kind: Service
metadata:
  name: echo
capabilities:
  - id: echo.say
    version: 1
subscriptions:
  - event: test.*
    mode: deliver
permissions:
  requested: [discover, invoke, event_subscribe]
```

`Recipe` is an alias for a service declaration. Service subscriptions use
`deliver`; they require the explicitly requested `event_subscribe` permission.
Capabilities describe offered verbs and do not grant permissions. Applying creates
a new participant each time, identified by the returned UUID; names are not unique.

Save the returned one-use activation credential privately and pass it to the
service SDK to connect. It remains unconsumed until registration. `--json` returns
`id`, `kind`, `name`, `network`, `subscriptions` and `activationCredential`, without
a summary prefix. The CLI does not persist this credential. If a successful
response is lost, an owner can issue a replacement activation credential through
`POST /api/v1/services/{id}/activation`; do not assume a failed connection means
nothing committed.

`pagnet service create <name> --network <network> --capability echo.say
--permission discover` uses the same transaction. Without `--network` it creates
only account-owned offline declarations. Network permissions are granted only
through explicit `--permission` flags. `--json` also completes the membership.

The small `pagnet.dev/v1` recipe format does not carry the runtime and encrypted
instructions required by account agent templates. `kind: AgentTemplate` is rejected
before any mutation; use the account agent-template API or console instead.
Invalid permissions, duplicate declarations, unsupported delivery modes, unknown
fields and multiple YAML documents are rejected before creation.
