import { DashboardStub } from "@/components/dashboard-stub";

export default function GovernanceDashboardPage() {
  return (
    <DashboardStub
      title="Governance"
      summary="Model inventory and AI governance. Delivered in F-013."
      planned={[
        "Model inventory",
        "Classifier model selection per tenant",
        "Shadow-AI detection feed (F-007 egress monitor)",
      ]}
    />
  );
}
