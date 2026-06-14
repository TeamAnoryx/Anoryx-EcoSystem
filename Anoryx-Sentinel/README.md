# Anoryx Sentinel

Zero-trust AI gateway for the Anoryx EcoSystem — a reverse proxy that inspects, masks,
governs, and logs all AI traffic between enterprise systems and the models they use.
Sentinel is the data path every other Anoryx product (Anoryx-AI-Orchestrator, Delta,
Rendly) depends on, and is built first. See `docs/adr/0001-build-sentinel-first.md` for
build order, `contracts/` for the locked Phase 0 integration boundary, and `CLAUDE.md`
for engineering standards.
