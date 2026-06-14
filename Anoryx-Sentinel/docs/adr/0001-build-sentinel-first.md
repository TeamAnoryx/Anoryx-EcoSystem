# ADR-0001: Build Anoryx Sentinel First

**Date:** 2026-06-14  |  **Status:** Accepted

## Context
Anoryx EcoSystem = Sentinel (security/governance gateway) + Anoryx-AI-Orchestrator
(bidirectional broker) + Delta (FinOps/ERP) + Rendly. We need a build order.

## Decision
Build Sentinel first. It is the data path all other products pass through.
- Delta's FinOps metering reuses Sentinel's per-request usage events.
- Anoryx-AI-Orchestrator brokers between Sentinel (events up) and Delta (policy down).
- Rendly's AI traffic runs through Sentinel.

## Ecosystem data flow (referenced by all future ADRs)

Sentinel emits events → Anoryx-AI-Orchestrator → Delta (cost/risk analytics)
Delta sets budget policies → Anoryx-AI-Orchestrator → Sentinel (enforcement)
The killer feature: over-budget AI agent automatically throttled at the gateway.

## Consequences
- Anoryx-Sentinel/contracts/ is locked in Phase 0 and treated as immutable by all products.
- Orchestration hooks (event emitter + policy intake) are built in Phase 1b, before Delta.
- Sentinel is the first product to undergo its own SOC 2 process.
