"""Optional macOS menubar host for the hermes-mac daemon.

Running the daemon inside a real app (HermesMacAgent.app) scopes the Screen
Recording / Accessibility TCC grants to the app's code-signing identity
instead of a terminal or raw Python binary.
"""

from hermes_mac_agent.menubar.app import ServerController, main

__all__ = ["ServerController", "main"]
