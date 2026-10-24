import { loadDashboardData } from "@/lib/data";
import Lab from "@/components/views/Lab";
export const dynamic = "force-dynamic";
export default function Page() {
  return <Lab data={loadDashboardData()} />;
}
