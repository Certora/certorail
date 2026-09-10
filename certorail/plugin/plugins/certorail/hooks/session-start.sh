#!/bin/sh
# certorail SessionStart hook: put the ambient policy's interface into the session context.
# Stdout becomes context the agent sees; silence adds nothing; never block the session.
if command -v certorail >/dev/null 2>&1; then
    exec certorail session-hook
fi
exit 0
