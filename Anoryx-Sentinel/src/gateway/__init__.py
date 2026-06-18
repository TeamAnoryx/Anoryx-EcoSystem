"""Anoryx Sentinel — Gateway Core (F-004).

``__version__`` is the single source of truth for the deployable release version
(F-010, ADR-0012 §8). It is distinct from the FastAPI app's ``version`` field in
``main.py`` (which versions the OpenAI-compatible API surface, not the release).
The health endpoints (``routes/health.py``) and the container/Helm tooling read
this constant.
"""

__version__ = "0.10.0"
