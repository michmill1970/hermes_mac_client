"""Client subpackage: Hermes-facing Python client library."""

from hermes_mac_agent.client.mac_agent import (
    BlockedByPolicyError,
    MacAgent,
    MacAgentError,
    TccPermissionError,
)

__all__ = ["MacAgent", "MacAgentError", "BlockedByPolicyError", "TccPermissionError"]
