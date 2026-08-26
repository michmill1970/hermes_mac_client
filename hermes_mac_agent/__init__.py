"""Hermes Mac agent — remote control of a MacBook Pro from the Hermes agent.

Public API:
    from hermes_mac_agent import MacAgent

    agent = MacAgent(host="192.168.1.50", port=8765, token="...", ca_cert="~/.hermes_mac_agent/ca.pem")
    img = agent.screenshot()
    agent.launch_app("Safari", url="https://www.linkedin.com")
"""

from hermes_mac_agent.client.mac_agent import MacAgent

__all__ = ["MacAgent"]
__version__ = "0.1.0"
