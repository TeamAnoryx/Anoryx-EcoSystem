"""Anoryx-Sentinel orchestration package (F-005).

Provides (F-005 scope):
  - Hook framework (hooks/base.py, registry.py, context.py, exceptions.py)
  - Four inspection detectors (detectors/)
  - Configuration (config.py)

Note: the event-bus emitter, policy-intake API, and internal mTLS channel
listed in the package charter are owned by a separate task and are NOT part
of F-005. F-005 detection events are persisted via the privileged-session
audit-chain path (see context.emit()), not via a stream emitter.
"""
