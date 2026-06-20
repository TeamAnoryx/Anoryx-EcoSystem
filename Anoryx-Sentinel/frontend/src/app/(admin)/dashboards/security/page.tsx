import { DashboardStub } from "@/components/dashboard-stub";

export default function SecurityDashboardPage() {
  return (
    <DashboardStub
      title="Security"
      summary="Real-time security posture across tenants. Delivered in F-013."
      planned={[
        "Real-time event feed (WebSocket)",
        "Per-team / per-model breakdowns",
        "Signature / hash-chain verification status",
      ]}
    />
  );
}
