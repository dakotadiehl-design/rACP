# Scenarios

Scenario files are strict JSON, or YAML when PyYAML is installed. Required keys are `schema_version`, `id`, `name`, `simulate`, `profile`, and `steps`. Unknown keys fail validation.

Supported steps are `connect`, `disconnect`, `send`, `invoke`, `navigate`, `expect`, `expect_none`, `expect_state_change`, `assert_state`, and `sleep`.

Values may reference `${variable}`. The runner defines `last_message_id`, `last_invocation_id`, and captured variables. `expect` may capture dotted envelope paths.

Stateful scenarios must independently expect the correlated command acknowledgement and a target-published authoritative state change.

