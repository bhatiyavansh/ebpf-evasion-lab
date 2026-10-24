import { loadDashboardData } from "@/lib/data";
import Demo from "@/components/views/Demo";
export const dynamic = "force-dynamic";
export default function Page() {
  return <Demo data={loadDashboardData()} />;
}
