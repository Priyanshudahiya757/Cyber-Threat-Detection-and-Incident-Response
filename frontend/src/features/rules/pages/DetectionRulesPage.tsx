/**
 * Detection Rules — every rule the engine runs, with its MITRE mapping.
 * Admins can switch rules on or off and tune their thresholds; changes
 * apply to the running engine immediately and survive restarts.
 */
import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { SlidersHorizontal } from "lucide-react";
import { ruleService } from "@/services/ruleService";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { getErrorMessage } from "@/lib/apiError";
import { humanize } from "@/lib/format";
import { Badge, Button, Card, CardBody, CardHeader, CardTitle, Input, Notice, Spinner } from "@/components/ui";
import type { DetectionRule, RuleSettingValue } from "@/types";

/** Form state holds every setting as text; lists are comma-separated. */
function toDraft(rule: DetectionRule): Record<string, string> {
  return Object.fromEntries(
    Object.entries(rule.config).map(([name, value]) => [name, Array.isArray(value) ? value.join(", ") : String(value)])
  );
}

function fromDraft(rule: DetectionRule, draft: Record<string, string>): Record<string, RuleSettingValue> {
  return Object.fromEntries(
    Object.entries(draft).map(([name, text]) => [
      name,
      rule.settings[name]?.type === "string_list"
        ? text.split(",").map((item) => item.trim()).filter(Boolean)
        : Number(text),
    ])
  );
}

function RuleSettingsForm({ rule, onClose }: { rule: DetectionRule; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState(() => toDraft(rule));

  const saveMutation = useMutation({
    mutationFn: () => ruleService.update(rule.rule_name, { config: fromDraft(rule, draft) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["rules"] });
      onClose();
    },
  });

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    saveMutation.mutate();
  };

  return (
    <form onSubmit={handleSubmit} className="mt-4 space-y-4 rounded-md border border-border bg-base-700/30 p-4">
      <div className="grid gap-4 sm:grid-cols-2">
        {Object.entries(rule.settings).map(([name, spec]) => (
          <div key={name}>
            <Input
              label={humanize(name)}
              name={`${rule.rule_name}-${name}`}
              type={spec.type === "integer" ? "number" : "text"}
              min={spec.type === "integer" ? spec.min : undefined}
              max={spec.type === "integer" ? spec.max : undefined}
              value={draft[name] ?? ""}
              onChange={(event) => setDraft({ ...draft, [name]: event.target.value })}
            />
            <p className="mt-1 text-xs text-text-muted">
              {spec.type === "integer"
                ? `Between ${spec.min} and ${spec.max}. Default ${spec.default}.`
                : `Comma-separated. Default: ${spec.default.join(", ")}.`}
            </p>
          </div>
        ))}
      </div>
      {saveMutation.isError && <Notice tone="error">{getErrorMessage(saveMutation.error)}</Notice>}
      <div className="flex gap-2">
        <Button type="submit" size="sm" isLoading={saveMutation.isPending}>
          Save settings
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

export function DetectionRulesPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<string | null>(null);

  const rulesQuery = useQuery({ queryKey: ["rules"], queryFn: ruleService.list });

  const toggleMutation = useMutation({
    mutationFn: ({ name, enabled }: { name: string; enabled: boolean }) => ruleService.update(name, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });

  const rules = rulesQuery.data ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Detection Rules</h1>
        <p className="mt-1 text-sm text-text-secondary">
          {isAdmin
            ? "Enable, disable, or tune rules. Changes take effect immediately, without a restart."
            : "The rules currently protecting the environment. Only administrators can change them."}
        </p>
      </div>

      {toggleMutation.isError && <Notice tone="error">{getErrorMessage(toggleMutation.error)}</Notice>}

      <Card>
        <CardHeader>
          <CardTitle>
            Rule set ({rules.filter((rule) => rule.enabled).length} of {rules.length} enabled)
          </CardTitle>
        </CardHeader>
        <CardBody>
          {rulesQuery.isLoading ? (
            <div className="flex h-40 items-center justify-center">
              <Spinner />
            </div>
          ) : rulesQuery.isError ? (
            <Notice tone="error">{getErrorMessage(rulesQuery.error, "Could not load rules.")}</Notice>
          ) : (
            <ul className="divide-y divide-border">
              {rules.map((rule) => {
                const settingEntries = Object.entries(rule.config);
                return (
                  <li key={rule.rule_name} className="py-4">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0 flex-1">
                        <p className="font-medium text-text-primary">{humanize(rule.rule_name)}</p>
                        <p className="mt-0.5 text-sm text-text-secondary">{rule.description}</p>
                        <p className="mt-1 font-data text-2xs text-text-muted">{rule.mitre_technique}</p>
                        {settingEntries.length > 0 && editing !== rule.rule_name && (
                          <p className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-data text-xs text-text-secondary">
                            {settingEntries.map(([name, value]) => (
                              <span key={name}>
                                <span className="text-text-muted">{name}:</span>{" "}
                                {Array.isArray(value) ? value.join(", ") : value}
                              </span>
                            ))}
                          </p>
                        )}
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge tone={rule.enabled ? "success" : "neutral"}>
                          {rule.enabled ? "Enabled" : "Disabled"}
                        </Badge>
                        {isAdmin && settingEntries.length > 0 && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => setEditing(editing === rule.rule_name ? null : rule.rule_name)}
                          >
                            <SlidersHorizontal className="h-3.5 w-3.5" />
                            Tune
                          </Button>
                        )}
                        {isAdmin && (
                          <button
                            type="button"
                            role="switch"
                            aria-checked={rule.enabled}
                            aria-label={`${rule.enabled ? "Disable" : "Enable"} ${humanize(rule.rule_name)}`}
                            disabled={toggleMutation.isPending}
                            onClick={() => toggleMutation.mutate({ name: rule.rule_name, enabled: !rule.enabled })}
                            className={`relative h-6 w-11 rounded-full transition-colors disabled:opacity-50 ${
                              rule.enabled ? "bg-accent-cyan" : "bg-base-500"
                            }`}
                          >
                            <span
                              className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all ${
                                rule.enabled ? "left-5" : "left-0.5"
                              }`}
                            />
                          </button>
                        )}
                      </div>
                    </div>
                    {editing === rule.rule_name && (
                      <RuleSettingsForm rule={rule} onClose={() => setEditing(null)} />
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
