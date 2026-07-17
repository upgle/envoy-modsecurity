# Source layout

Runtime source will be introduced in two independently testable layers:

```text
source/
├── engine/                         # Envoy-independent ModSecurity adapter
│   ├── engine.{cc,h}
│   ├── rules.{cc,h}
│   └── transaction.{cc,h}
└── extensions/filters/http/modsecurity/
    ├── config.{cc,h}               # typed config and static registration
    ├── filter.{cc,h}               # Envoy stream callbacks and state machine
    └── stats.{cc,h}
```

The first runtime commit must include rule-load validation and request-path integration tests. It
must never register a no-op implementation under the production filter name.
