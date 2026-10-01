# Local Models: Configuration and Request Ownership

[English](#) · [中文](../local-model.md)

[Project home](../../README.md) · [Data-flow chapter](learning/08-sensitive-data-flow.md)

Fixed demos and offline learning need no model. For live experiments, start your own OpenAI-compatible model server and select a model actually installed there.

## Identify the sending process

| Request | Sender | Configuration |
| --- | --- | --- |
| Demo HTTP/MCP task and memory summary | Demo Agent process | `DEMO_MODEL_BASE_URL` must match gateway `AGENTSENTRY_MODEL_LOCAL_BASE_URL` |
| Optional output semantic hint | Gateway | `OUTPUT_LOCAL_MODEL_BASE_URL`, `OUTPUT_LOCAL_MODEL_NAME`; off by default |
| Optional goal semantic hint | Gateway | `GOAL_LOCAL_MODEL_BASE_URL`, `GOAL_LOCAL_MODEL_NAME`; off by default |
| Asynchronous Judge | Worker | Separate Judge settings and credentials |

For tasks/summaries the gateway checks messages and returns the registered address; the adapter sends the request. A gateway container’s loopback differs from host loopback, but the gateway does not send these task requests, so do not mechanically replace the registered Agent address with a container address.

## Agent and model on the host

1. Start a server supporting `/chat/completions` and tool calls. Automatic memory summaries also need JSON response format. Unsupported features are compatibility failures, not proof of a failed safety control.
2. Register the actual host model URL in `.env`, for example `AGENTSENTRY_MODEL_LOCAL_BASE_URL=http://127.0.0.1:11434/v1`. Recreate the Web container after changing its environment: `docker compose up -d --force-recreate web`.
3. In the online host terminal:

```bash
export SENTRY_URL='http://127.0.0.1:8000'
export AGENT_API_KEY='YOUR_AGENT_KEY'
export AGENT_CAPABILITIES_JSON='{"read_document":"YOUR_PUBLIC_GUIDE_CAPABILITY"}'
export DEMO_MODEL_BASE_URL='http://127.0.0.1:11434/v1'
export DEMO_MODEL_NAME='YOUR_INSTALLED_MODEL'
export AGENTSENTRY_MODEL_DESTINATION=local
.venv/bin/agentsentry-demo --scenario llm --prompt 'Read public-guide and summarize it.'
```

Replace all placeholders and ports. If your model needs authentication, set `DEMO_MODEL_API_KEY` in this trusted process. The standalone Agent reads environment variables, not `.env` automatically. Research runners generally load administrator settings and create research tenants, but still set the model URL/name explicitly.

4. Inspect source IDs, model preflight, output check and display in Web. No dangerous tool attempt means tool-blocking effectiveness remains unverified.

## Optional gateway hints

Only explicit `OUTPUT_LOCAL_MODEL_*` or `GOAL_LOCAL_MODEL_*` settings make the gateway send those hint requests. Docker Desktop may reach the host through `http://host.docker.internal:11434/v1`; verify DNS, listening address and firewall. Linux host mapping may need additional configuration; Compose does not add it automatically. Hints do not widen permissions or skip checks, and connection failure is recorded as analysis failure.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Destination mismatch | Agent and registered gateway URL must agree except trailing slash; do not interchange `localhost` and `127.0.0.1` |
| Agent connection refused | Test reachability from the Agent environment, model/path and proxy settings |
| Gateway hint connection refused | Container loopback is not the host; identify the hint sender |
| Model preflight denied | Inspect sources, destination, binding, budget and audit, rather than bypassing preflight |
| Running an entire lab inside Docker | Some runners recognize only loopback as local; `host.docker.internal` is not universally accepted |

Remote HTTPS models need explicit registration and runner permission, can incur costs and transmit data. The local instructions above do not enable them; see [data-flow configuration](data-flow.md).
