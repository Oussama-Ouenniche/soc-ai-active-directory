# Architecture notes

SOC-AI follows a hybrid detection pipeline:

1. **Collection** — Wazuh events are queried from OpenSearch using a bounded time window.
2. **Normalization** — relevant Active Directory fields are mapped into a Pandas DataFrame.
3. **UEBA** — behavioral features are constructed per user and time window.
4. **Detection** — individual modules evaluate brute-force patterns, IOC matches and contextual / ML signals.
5. **Prioritization** — severity, behavioral evidence and anomaly signals are combined into a SOC score.
6. **Response** — alerts are written to a dedicated OpenSearch index for dashboarding and investigation.

The public version excludes real deployment artifacts. Use the configuration templates to connect it to an isolated lab.
