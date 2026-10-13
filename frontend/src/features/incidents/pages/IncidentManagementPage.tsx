/**
 * Incident Management — triage, assign, comment, resolve, close.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { format, parseISO } from "date-fns";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { incidentService } from "@/services/incidentService";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { severityToTone } from "@/components/ui/badgeUtils";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import type { IncidentRecord, IncidentStatus, Severity } from "@/types";

const STATUS_TONE: Record<IncidentStatus, "info" | "warning" | "success" | "neutral"> = {
  OPEN: "warning",
  INVESTIGATING: "info",
  RESOLVED: "success",
  CLOSED: "neutral",
};

export function IncidentManagementPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | "">("");
  const [selectedRef, setSelectedRef] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [assignTo, setAssignTo] = useState(user?.username ?? "");

  const listQuery = useQuery({
    queryKey: ["incidents", "list", statusFilter],
    queryFn: () =>
      incidentService.list({
        status: statusFilter || undefined,
      }),
    refetchInterval: 15_000,
  });

  const detailQuery = useQuery({
    queryKey: ["incidents", "detail", selectedRef],
    queryFn: () => incidentService.get(selectedRef!),
    enabled: !!selectedRef,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["incidents"] });
    queryClient.invalidateQueries({ queryKey: ["analytics"] });
  };

  const statusMutation = useMutation({
    mutationFn: ({ ref, status, noteText }: { ref: string; status: IncidentStatus; noteText?: string }) =>
      incidentService.updateStatus(ref, { status, note: noteText }),
    onSuccess: (inc) => {
      setSelectedRef(inc.incident_ref);
      invalidate();
    },
  });

  const noteMutation = useMutation({
    mutationFn: ({ ref, text }: { ref: string; text: string }) =>
      incidentService.addNote(ref, { note: text }),
    onSuccess: () => {
      setNote("");
      invalidate();
      queryClient.invalidateQueries({ queryKey: ["incidents", "detail", selectedRef] });
    },
  });

  const assignMutation = useMutation({
    mutationFn: ({ ref, who }: { ref: string; who: string }) => incidentService.assign(ref, who),
    onSuccess: () => {
      invalidate();
      queryClient.invalidateQueries({ queryKey: ["incidents", "detail", selectedRef] });
    },
  });

  const selected: IncidentRecord | undefined = detailQuery.data;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-text-primary">Incident Management</h1>
          <p className="mt-1 text-sm text-text-secondary">
            Correlated detections with analyst workflow and investigation timeline.
          </p>
        </div>
        <select
          className="h-10 rounded-md border border-border bg-base-800 px-3 text-sm"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as IncidentStatus | "")}
        >
          <option value="">All statuses</option>
          <option value="OPEN">Open</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="RESOLVED">Resolved</option>
          <option value="CLOSED">Closed</option>
        </select>
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Incidents ({listQuery.data?.count ?? 0})</CardTitle>
          </CardHeader>
          <CardBody className="max-h-[640px] space-y-2 overflow-y-auto p-3">
            {listQuery.isLoading && (
              <div className="flex h-32 items-center justify-center">
                <Spinner />
              </div>
            )}
            {(listQuery.data?.incidents ?? []).map((inc) => (
              <button
                key={inc.incident_ref}
                type="button"
                onClick={() => setSelectedRef(inc.incident_ref)}
                className={`w-full rounded-md border px-3 py-3 text-left transition-colors ${
                  selectedRef === inc.incident_ref
                    ? "border-accent-cyan/50 bg-accent-cyan/10"
                    : "border-border bg-base-700/40 hover:border-accent-cyan/30"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-data text-sm text-accent-cyan">{inc.incident_ref}</span>
                  <Badge tone={severityToTone(inc.severity as Severity)} />
                </div>
                <p className="mt-1 text-sm text-text-primary">{inc.threat_type}</p>
                <div className="mt-2 flex items-center justify-between">
                  <Badge tone={STATUS_TONE[inc.status]}>{inc.status}</Badge>
                  <span className="font-data text-2xs text-text-muted">{inc.entity.value}</span>
                </div>
              </button>
            ))}
            {!listQuery.isLoading && (listQuery.data?.incidents?.length ?? 0) === 0 && (
              <p className="py-8 text-center text-sm text-text-muted">
                No incidents yet — upload attack sample logs to generate them.
              </p>
            )}
          </CardBody>
        </Card>

        <Card className="lg:col-span-3">
          <CardHeader>
            <CardTitle>{selected ? selected.incident_ref : "Select an incident"}</CardTitle>
          </CardHeader>
          <CardBody>
            {!selectedRef && (
              <p className="py-12 text-center text-sm text-text-muted">
                Choose an incident from the list to view timeline and actions.
              </p>
            )}
            {selectedRef && detailQuery.isLoading && (
              <div className="flex h-40 items-center justify-center">
                <Spinner />
              </div>
            )}
            {selected && (
              <div className="space-y-5">
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <p className="text-2xs uppercase text-text-muted">Threat</p>
                    <p className="text-sm text-text-primary">{selected.threat_type}</p>
                  </div>
                  <div>
                    <p className="text-2xs uppercase text-text-muted">Entity</p>
                    <p className="font-data text-sm text-accent-cyan">{selected.entity.value}</p>
                  </div>
                  <div>
                    <p className="text-2xs uppercase text-text-muted">Assigned to</p>
                    <p className="text-sm text-text-primary">{selected.assigned_to ?? "Unassigned"}</p>
                  </div>
                  <div>
                    <p className="text-2xs uppercase text-text-muted">Status</p>
                    <Badge tone={STATUS_TONE[selected.status]}>{selected.status}</Badge>
                  </div>
                </div>

                <p className="text-sm text-text-secondary">{selected.description}</p>

                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={selected.status !== "OPEN"}
                    isLoading={statusMutation.isPending}
                    onClick={() =>
                      statusMutation.mutate({
                        ref: selected.incident_ref,
                        status: "INVESTIGATING",
                        noteText: "Moved to investigating",
                      })
                    }
                  >
                    Investigate
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={selected.status === "CLOSED" || selected.status === "RESOLVED"}
                    onClick={() =>
                      statusMutation.mutate({
                        ref: selected.incident_ref,
                        status: "RESOLVED",
                        noteText: "Marked resolved",
                      })
                    }
                  >
                    Resolve
                  </Button>
                  <Button
                    size="sm"
                    variant="danger"
                    disabled={selected.status === "CLOSED"}
                    onClick={() =>
                      statusMutation.mutate({
                        ref: selected.incident_ref,
                        status: "CLOSED",
                        noteText: "Incident closed",
                      })
                    }
                  >
                    Close
                  </Button>
                </div>

                <div className="flex flex-wrap items-end gap-2">
                  <div className="min-w-[160px] flex-1">
                    <Input
                      label="Assign analyst"
                      value={assignTo}
                      onChange={(e) => setAssignTo(e.target.value)}
                    />
                  </div>
                  <Button
                    size="sm"
                    onClick={() =>
                      assignMutation.mutate({ ref: selected.incident_ref, who: assignTo })
                    }
                    isLoading={assignMutation.isPending}
                    disabled={!assignTo.trim()}
                  >
                    Assign
                  </Button>
                </div>

                <div className="flex flex-wrap items-end gap-2">
                  <div className="min-w-[200px] flex-1">
                    <Input
                      label="Add comment"
                      value={note}
                      onChange={(e) => setNote(e.target.value)}
                      placeholder="Investigation note…"
                    />
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() =>
                      noteMutation.mutate({ ref: selected.incident_ref, text: note })
                    }
                    isLoading={noteMutation.isPending}
                    disabled={!note.trim()}
                  >
                    Post
                  </Button>
                </div>

                <div>
                  <h3 className="mb-3 text-sm font-semibold text-text-primary">Timeline</h3>
                  <ol className="space-y-3 border-l border-border pl-4">
                    {(selected.investigation_notes ?? []).map((n, idx) => (
                      <li key={`${n.created_at}-${idx}`} className="relative">
                        <span className="absolute -left-[1.15rem] top-1.5 h-2 w-2 rounded-full bg-accent-cyan" />
                        <p className="text-sm text-text-primary">{n.note}</p>
                        <p className="font-data text-2xs text-text-muted">
                          {n.author} ·{" "}
                          {n.created_at ? format(parseISO(n.created_at), "MMM d HH:mm:ss") : ""}
                        </p>
                      </li>
                    ))}
                  </ol>
                </div>
              </div>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
