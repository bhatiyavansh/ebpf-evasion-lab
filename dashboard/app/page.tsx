import { loadDashboardData } from "@/lib/data";
import Home from "@/components/views/Home";
export const dynamic = "force-dynamic";
export default function Page() {
  return <Home data={loadDashboardData()} />;
}
