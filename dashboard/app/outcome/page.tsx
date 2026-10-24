import { loadDashboardData } from "@/lib/data";
import Outcome from "@/components/views/Outcome";
export const dynamic = "force-dynamic";
export default function Page() {
  return <Outcome data={loadDashboardData()} />;
}
