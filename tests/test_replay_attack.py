"""
Replay attack 

GOAL: Replay old signed submission 

Expected: Token registry blocks reuse.
"""

from server.token_store import TokenRegistry

def test_replay_blocked():

    registry = TokenRegistry()

    token_hash = "abc123"

    registry.mark_used(token_hash)

    assert registry.is_used(token_hash) is True