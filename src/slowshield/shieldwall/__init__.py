"""Shield wall: one leader instance, many followers (docs/design/shieldwall.md).

A follower is a complete SlowShield that can always run on its own. Paired with a leader, it reports its events and
statistics, takes policy, blocks and observations from it within limits it keeps itself, and fetches package files
through it while the leader is reachable. Followers dial out; the leader never connects to them.
"""
