import { loadDashboardData } from "@/lib/data";
import TraceWeaverApp from "@/components/TraceWeaverApp";
export const dynamic = "force-dynamic";
export default function Page() {
  return <TraceWeaverApp data={loadDashboardData()} />;
}
