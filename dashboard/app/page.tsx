import { loadExperiments } from "@/lib/data";
import Dashboard from "@/components/Dashboard";

export const dynamic = "force-dynamic";

export default function Page() {
  const experiments = loadExperiments();
  return <Dashboard experiments={experiments} />;
}
