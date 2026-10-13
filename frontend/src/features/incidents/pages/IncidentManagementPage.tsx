/**
 * Incident Management — triage, assign, comment, resolve, close.
 */
import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { incidentService } from "@/services/incidentService";
import { userService } from "@/services/userService";
import { getErrorMessage } from "@/lib/apiError";
import { formatDateTime } from "@/lib/format";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Input,
  Notice,
  Select,
  Spinner,
} from "@/components/ui";
import { INCIDENT_STATUSES, type IncidentRecord, type IncidentStatus } from "@/types";

const STATUS_TONE: Record<IncidentStatus, "info" | "warning" | "success" | "neutral"> = {
  OPEN: "warning",
  INVESTIGATING: "info",
  RESOLVED: "success",
  CLOSED: "neutral",
};

/** Status buttons offered for each current status, mirroring the backend's transition rules. */
const NEXT_STATUSES: Record<IncidentStatus, { status: IncidentStatus; label: string }[]> = {
  OPEN: [
    { status: "INVESTIGATING", label: "Investigate" },
    { status: "RESOLVED", label: "Resolve" },
    { status: "CLOSED", label: "Close" },
  ],
  INVESTIGATING: [
    { status: "RESOLVED", label: "Resolve" },
    { status: "CLOSED", label: "Close" },
  ],
  RESOLVED: [
    { status: "INVESTIGATING", label: "Reopen" },
    { status: "CLOSED", label: "Close" },
  ],
  CLOSED: [],
};

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <p className="text-2xs uppercase text-text-muted">{label}</p>
      <div className="mt-0.5 text-sm text-text-primary">{children}</div>
    </div>
  );
}

function IncidentDetail({ incident }: { incident: IncidentRecord }) {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [note, setNote] = useState("");
  const [assignee, setAssignee] = useState(incident.assigned_to ?? user?.username ?? "");
  const [error, setError] = useState<string | null>(null);

  const assignableQuery = useQuery({ queryKey: ["users", "assignable"], queryFn: userService.listAssignable });
  const isClosed = incident.status === "CLOSED";

  const mutationOptions = {
    onSuccess: (updated: IncidentRecord) => {
      setError(null);
      queryClient.setQueryData(["incidents", "detail", updated.incident_ref], updated);
      queryClient.invalidateQueries({ queryKey: ["incidents", "list"] });
      queryClient.invalidateQueries({ queryKey: ["analytics"] });
    },
    onError: (err: unknown) => setError(getErrorMessage(err)),
  };

  const statusMutation = useMutation({
    mutationFn: (status: IncidentStatus) => incidentService.updateStatus(incident.incident_ref, { status }),
    ...mutationOptions,
  });

  const assignMutation = useMutation({
    mutationFn: () => incidentService.assign(incident.incident_ref, assignee),
    ...mutationOptions,
  });

  const noteMutation = useMutation({
    mutationFn: () => incidentService.addNote(incident.incident_ref, note.trim()),
    ...mutationOptions,
    onSuccess: (updated: IncidentRecord) => {
      setNote("");
      mutationOptions.onSuccess(updated);
    },
  });

  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Threat">{incident.threat_type}</Field>
        <Field label="Entity">
          <span className="font-data text-accent-cyan">{incident.entity.value}</span>
          <span className="ml-2 text-2xs uppercase text-text-muted">{incident.entity.type}</span>
        </Field>
        <Field label="Severity">
          <Badge tone={incident.severity} />
        </Field>
        <Field label="Status">
          <Badge tone={STATUS_TONE[incident.status]}>{incident.status}</Badge>
        </Field>
        <Field label="Assigned to">{incident.assigned_to ?? "Unassigned"}</Field>
        <Field label="MITRE ATT&CK">{incident.mitre_technique ?? "—"}</Field>
        <Field label="Opened">
          <span className="font-data">{formatDateTime(incident.created_at)}</span>
        </Field>
        <Field label="Evidence">
          {incident.detection_ids.length} detection(s), {incident.evidence_log_ids.length} log(s)
        </Field>
      </div>

      <p className="text-sm text-text-secondary">{incident.description}</p>

      {error && <Notice tone="error">{error}</Notice>}

      {isClosed ? (
        <p className="text-sm text-text-muted">This incident is closed and kept for the audit trail.</p>
      ) : (
        <>
          <div className="flex flex-wrap gap-2">
            {NEXT_STATUSES[incident.status].map(({ status, label }) => (
              <Button
                key={status}
                size="sm"
                variant={status === "CLOSED" ? "danger" : "outline"}
                disabled={statusMutation.isPending}
                onClick={() => statusMutation.mutate(status)}
              >
                {label}
              </Button>
            ))}
          </div>

          <div className="flex flex-wrap items-end gap-2">
            <Select
              label="Assign analyst"
              name="assignee"
              className="min-w-[180px]"
              value={assignee}
              onChange={(event) => setAssignee(event.target.value)}
            >
              <option value="" disabled>
                Select a user
              </option>
              {(assignableQuery.data ?? []).map((username) => (
                <option key={username} value={username}>
                  {username}
                </option>
              ))}
            </Select>
            <Button
              onClick={() => assignMutation.mutate()}
              isLoading={assignMutation.isPending}
              disabled={!assignee || assignee === incident.assigned_to}
            >
              Assign
            </Button>
          </div>
        </>
      )}

      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          noteMutation.mutate();
        }}
      >
        <div className="min-w-[200px] flex-1">
          <Input
            label="Add investigation note"
            name="note"
            value={note}
            maxLength={2000}
            onChange={(event) => setNote(event.target.value)}
            placeholder="What did you find?"
          />
        </div>
        <Button type="submit" variant="outline" isLoading={noteMutation.isPending} disabled={!note.trim()}>
          Post
        </Button>
      </form>

      <div>
        <h3 className="mb-3 text-sm font-semibold text-text-primary">Timeline</h3>
        <ol className="space-y-3 border-l border-border pl-4">
          {incident.investigation_notes.map((entry, index) => (
            <li key={`${entry.created_at}-${index}`} className="relative">
              <span className="absolute -left-[1.15rem] top-1.5 h-2 w-2 rounded-full bg-accent-cyan" />
              <p className="text-sm text-text-primary">{entry.note}</p>
              <p className="font-data text-2xs text-text-muted">
                {entry.author} · {formatDateTime(entry.created_at)}
              </p>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}

export function IncidentManagementPage() {
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | "">("");
  const [selectedRef, setSelectedRef] = useState<string | null>(null);

  const listQuery = useQuery({
    queryKey: ["incidents", "list", statusFilter],
    queryFn: () => incidentService.list({ status: statusFilter || undefined }),
    refetchInterval: 15_000,
  });

  const detailQuery = useQuery({
    queryKey: ["incidents", "detail", selectedRef],
    queryFn: () => incidentService.get(selectedRef!),
    enabled: !!selectedRef,
  });

  const incidents = listQuery.data?.incidents ?? [];
  const selected = detailQuery.data;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-text-primary">Incident Management</h1>
          <p className="mt-1 text-sm text-text-secondary">
            Correlated detections with analyst workflow and investigation timeline.
          </p>
        </div>
        <Select
          aria-label="Filter by status"
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value as IncidentStatus | "")}
        >
          <option value="">All statuses</option>
          {INCIDENT_STATUSES.map((status) => (
            <option key={status} value={status}>
              {status.charAt(0) + status.slice(1).toLowerCase()}
            </option>
          ))}
        </Select>
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Incidents ({incidents.length})</CardTitle>
          </CardHeader>
          <CardBody className="max-h-[640px] space-y-2 overflow-y-auto p-3">
            {listQuery.isLoading && (
              <div className="flex h-32 items-center justify-center">
                <Spinner />
              </div>
            )}
            {listQuery.isError && (
              <Notice tone="error">{getErrorMessage(listQuery.error, "Could not load incidents.")}</Notice>
            )}
            {incidents.map((incident) => (
              <button
                key={incident.incident_ref}
                type="button"
                onClick={() => setSelectedRef(incident.incident_ref)}
                className={`w-full rounded-md border px-3 py-3 text-left transition-colors ${
                  selectedRef === incident.incident_ref
                    ? "border-accent-cyan/50 bg-accent-cyan/10"
                    : "border-border bg-base-700/40 hover:border-accent-cyan/30"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-data text-sm text-accent-cyan">{incident.incident_ref}</span>
                  <Badge tone={incident.severity} />
                </div>
                <p className="mt-1 text-sm text-text-primary">{incident.threat_type}</p>
                <div className="mt-2 flex items-center justify-between">
                  <Badge tone={STATUS_TONE[incident.status]}>{incident.status}</Badge>
                  <span className="font-data text-2xs text-text-muted">{incident.entity.value}</span>
                </div>
              </button>
            ))}
            {listQuery.isSuccess && incidents.length === 0 && (
              <p className="py-8 text-center text-sm text-text-muted">
                {statusFilter
                  ? "No incidents with this status."
                  : "No incidents yet — upload logs to generate them."}
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
                Choose an incident from the list to view its timeline and actions.
              </p>
            )}
            {selectedRef && detailQuery.isLoading && (
              <div className="flex h-40 items-center justify-center">
                <Spinner />
              </div>
            )}
            {selectedRef && detailQuery.isError && (
              <Notice tone="error">{getErrorMessage(detailQuery.error, "Could not load this incident.")}</Notice>
            )}
            {/* Keyed by incident so the note/assignee inputs reset when another one is selected. */}
            {selected && <IncidentDetail key={selected.incident_ref} incident={selected} />}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
