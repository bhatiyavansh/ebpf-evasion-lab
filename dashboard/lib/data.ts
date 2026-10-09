import fs from "fs";
import path from "path";

export type Tool = "falco" | "tracee" | "tetragon";

export type StatusKind = "detected" | "observed" | "partial" | "not_tested" | "missed";

export interface CellResult {
  status: StatusKind;
  badge: string;
  summary: string;
  detectionType: string | null;
  processesObserved: string[] | null;
  alertCount: number | null;
  evidencePath: string | null;
  raw: Record<string, unknown> | null;
}

export interface ExperimentDef {
  id: string;
  title: string;
  behavior: string;
  description: string;
  commands: Partial<Record<Tool, string>>;
  variant: string;
}

export interface ExperimentRow extends ExperimentDef {
  cells: Partial<Record<Tool, CellResult>>;
}

const REPO_ROOT = path.join(process.cwd(), "..");

function readJson(relPath: string): Record<string, unknown> | null {
  const full = path.join(REPO_ROOT, relPath);
  if (!fs.existsSync(full)) return null;
  try {
    return JSON.parse(fs.readFileSync(full, "utf-8"));
  } catch {
    return null;
  }
}

const EXPERIMENT_TITLES: Record<string, { title: string; behavior: string }> = {
  E01: { title: "Sensitive File Access", behavior: "sensitive_file_read" },
  E02: { title: "Process Execution", behavior: "process_execution" },
  E03: { title: "Network Activity", behavior: "network_activity" },
  E04: { title: "Indirect Execution", behavior: "indirect_process_execution" },
  E05: { title: "Timing Variation", behavior: "timing_variation" },
};

const EXPERIMENT_FILES: Record<string, string[]> = {
  E01: ["experiments/E01_sensitive_file_read.json"],
  E02: ["experiments/E02_process_execution.json", "experiments/E02_process_execution_tracee.json"],
  E03: ["experiments/E03_network_activity.json"],
  E04: [
    "experiments/E04_indirect_process_execution.json",
    "experiments/E04_indirect_process_execution_tracee.json",
  ],
  E05: ["experiments/E05_timing_variation.json", "experiments/E05_timing_variation_tracee.json"],
};

const RAW_FILES: Record<string, Partial<Record<Tool, string>>> = {
  E01: {
    falco: "results/raw/E01_falco.json",
    tracee: "results/raw/E01_tracee.json",
    tetragon: "results/raw/E01_tetragon.json",
  },
  E02: { falco: "results/raw/E02_falco.json", tracee: "results/raw/E02_tracee.json" },
  E03: { falco: "results/raw/E03_falco.json", tracee: "results/raw/E03_tracee.json" },
  E04: { falco: "results/raw/E04_falco.json", tracee: "results/raw/E04_tracee.json" },
  E05: { falco: "results/raw/E05_falco.json", tracee: "results/raw/E05_tracee.json" },
};

/**
 * Status is derived from repository evidence only. Tracee has no alerting
 * engine configured in this lab (execve/openat/connect telemetry only), so
 * its results are always "observed", never "detected", regardless of the
 * `detected` boolean in its raw JSON. Falco has an active rule engine, so a
 * rule firing is a genuine detection — except where the raw result itself
 * says the fired rule doesn't cover the tested behavior (E03 network).
 */
function deriveCell(tool: Tool, experimentId: string, raw: Record<string, unknown> | null, evidencePath: string): CellResult {
  if (!raw) {
    return {
      status: "not_tested",
      badge: "NOT TESTED",
      summary: "No result file exists in the repository for this tool/experiment combination.",
      detectionType: null,
      processesObserved: null,
      alertCount: null,
      evidencePath: null,
      raw: null,
    };
  }

  const detectionType = (raw.detection_type as string) ?? null;
  const processesObserved = (raw.processes_detected as string[]) ?? null;
  const alertCount = (raw.alert_count as number) ?? null;
  const notes = (raw.notes as string) ?? "";
  const detected = raw.detected === true;
  const eventObserved = raw.event_observed === true;

  if (tool === "tracee") {
    return {
      status: "observed",
      badge: "OBSERVED",
      summary: notes || "Telemetry observed via configured eBPF event set.",
      detectionType,
      processesObserved,
      alertCount,
      evidencePath,
      raw,
    };
  }

  if (tool === "tetragon") {
    if (!eventObserved) {
      return {
        status: "not_tested",
        badge: "NOT TESTED",
        summary: notes || "No telemetry recorded for this experiment.",
        detectionType,
        processesObserved,
        alertCount,
        evidencePath,
        raw,
      };
    }
    if (!detected) {
      return {
        status: "partial",
        badge: "PARTIAL",
        summary: notes || "Telemetry observed; detection status not established.",
        detectionType,
        processesObserved,
        alertCount,
        evidencePath,
        raw,
      };
    }
    return {
      status: "detected",
      badge: "DETECTED",
      summary: notes,
      detectionType,
      processesObserved,
      alertCount,
      evidencePath,
      raw,
    };
  }

  // Falco: has an active rule engine. E03 is a known special case where the
  // fired rule is process-execution, not the network-specific behavior under
  // test, so the repository explicitly flags network_connection_detection: false.
  if (experimentId === "E03" && raw.network_connection_detection === false) {
    return {
      status: "partial",
      badge: "PROCESS TELEMETRY ONLY",
      summary: notes,
      detectionType: detectionType ?? "process_execution",
      processesObserved,
      alertCount,
      evidencePath,
      raw,
    };
  }

  if (detected) {
    return {
      status: "detected",
      badge: "DETECTED",
      summary: notes,
      detectionType,
      processesObserved,
      alertCount,
      evidencePath,
      raw,
    };
  }

  if (eventObserved) {
    return {
      status: "observed",
      badge: "OBSERVED",
      summary: notes || "Telemetry observed; no rule fired.",
      detectionType,
      processesObserved,
      alertCount,
      evidencePath,
      raw,
    };
  }

  return {
    status: "missed",
    badge: "NOT DETECTED",
    summary: notes || "Rule engine did not fire and no telemetry was recorded.",
    detectionType,
    processesObserved,
    alertCount,
    evidencePath,
    raw,
  };
}

export function loadExperiments(): ExperimentRow[] {
  const ids = ["E01", "E02", "E03", "E04", "E05"];
  return ids.map((id) => {
    const meta = EXPERIMENT_TITLES[id];
    const defFiles = EXPERIMENT_FILES[id].map((f) => readJson(f)).filter(Boolean) as Record<string, unknown>[];
    const commands: Partial<Record<Tool, string>> = {};
    let description = "";
    let variant = "baseline";
    for (const def of defFiles) {
      const tool = def.tool as Tool;
      commands[tool] = def.command as string;
      description = (def.description as string) || description;
      variant = (def.variant as string) || variant;
    }

    const raw = RAW_FILES[id] ?? {};
    const cells: Partial<Record<Tool, CellResult>> = {};
    (["falco", "tracee", "tetragon"] as Tool[]).forEach((tool) => {
      const relPath = raw[tool];
      const data = relPath ? readJson(relPath) : null;
      cells[tool] = deriveCell(tool, id, data, relPath ?? "");
    });

    return {
      id,
      title: meta.title,
      behavior: meta.behavior,
      description,
      commands,
      variant,
      cells,
    };
  });
}

export function readEvidenceFile(relPath: string): Record<string, unknown> | null {
  if (!relPath.startsWith("results/raw/") && !relPath.startsWith("experiments/")) return null;
  return readJson(relPath);
}
