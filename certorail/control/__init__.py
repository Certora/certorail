"""The control plane: what manages the config directory and the agent's context, as opposed to
analysing and running programs. ``install`` (policies and ruleset packs into the config
directory: ``certorail policy``), ``apply`` (a ruleset into a policy, and the inventory),
``init`` (first-run setup and the per-directory interview) and ``session_hook`` (the Claude
Code SessionStart hook). ``certorail.host`` dispatches the verbs here; nothing in the analysis
imports from this package."""
