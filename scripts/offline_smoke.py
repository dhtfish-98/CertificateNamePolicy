"""Use installed API/CLI with Python network audit events actively blocked."""

import json
import sys


def forbid_network(event, args):
    if event.startswith("socket."):
        raise AssertionError("network event forbidden during offline validation")


sys.addaudithook(forbid_network)

from certificate_name_policy.cli import main  # noqa: E402

code = main(sys.argv[1:])
print(json.dumps({"offline_network_audit": "enabled", "exit_code": code}), file=sys.stderr)
raise SystemExit(code)
