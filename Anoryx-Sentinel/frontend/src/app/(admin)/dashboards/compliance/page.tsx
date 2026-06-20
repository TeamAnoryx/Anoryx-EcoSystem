import { DashboardStub } from "@/components/dashboard-stub";

export default function ComplianceDashboardPage() {
  return (
    <DashboardStub
      title="Compliance"
      summary="Audit-ready posture and evidence. Delivered in F-013."
      planned={[
        "Readiness score (SOC 2 / ISO 27001)",
        "Gap report",
        "Evidence pack download",
      ]}
    />
  );
}
