# Agent endpoint boundaries

An agent's network description is searchable metadata. Creating a configured
local agent uses that description as its standing role unless the owner supplies
an explicit private role. A private override does not replace the public
description and neither text grants authority or chooses tools, credentials or
executables. Creation submits no runtime turn.

The ordinary configured native endpoint accepts exactly `{"input":"text"}`.
DESCRIBE returns `extensions.pagnet.agent.input_schema` and
`extensions.pagnet.agent.input_limits`. The schema requires a nonempty string and
rejects additional properties. The runtime also requires valid UTF-8 and at most
131,072 bytes of input text; JSON Schema character counts cannot express that
byte constraint. The text reaches the existing native driver without rewriting.
DISCOVER excludes this schema from the compact search document. This default
input grammar does not require a structured offer or a second target reference.

Existing hosted agents retain their original cloud-native worker authority.
Their database instance ID, runtime session ID or saved transcript does not
authorize creating a replacement local worker. Integration must retain the
original authenticated daemon, ownership generation, dispatch admission and
native source journal. `Adapter` consumes the trusted lifecycle boundary; it
does not mint any of those facts itself.
