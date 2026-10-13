/**
 * Detection Rules — enable/disable persisted rule configuration.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ruleService } from "@/services/ruleService";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";

export function DetectionRulesPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const queryClient = useQueryClient();

  const rulesQuery = useQuery({
    queryKey: ["rules"],
    queryFn: () => ruleService.list(),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ name, enabled }: { name: string; enabled: boolean }) =>
      ruleService.update(name, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Detection Rules</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Live rule engine configuration. Admins can enable or disable rules without redeploy.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Rule set ({rulesQuery.data?.rules.length ?? 0})</CardTitle>
        </CardHeader>
        <CardBody>
          {rulesQuery.isLoading ? (
            <div className="flex h-40 items-center justify-center">
              <Spinner />
            </div>
          ) : (
            <ul className="divide-y divide-border">
              {(rulesQuery.data?.rules ?? []).map((rule) => (
                <li
                  key={rule.rule_name}
                  className="flex flex-wrap items-center justify-between gap-3 py-4"
                >
                  <div className="min-w-0 flex-1">
                    <p className="font-medium text-text-primary">
                      {rule.rule_name.replace(/_/g, " ")}
                    </p>
                    <p className="mt-0.5 text-sm text-text-secondary">{rule.description}</p>
                    <p className="mt-1 font-data text-2xs text-text-muted">{rule.mitre_technique}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge tone={rule.enabled ? "success" : "neutral"}>
                      {rule.enabled ? "Enabled" : "Disabled"}
                    </Badge>
                    {isAdmin && (
                      <button
                        type="button"
                        disabled={toggleMutation.isPending}
                        onClick={() =>
                          toggleMutation.mutate({
                            name: rule.rule_name,
                            enabled: !rule.enabled,
                          })
                        }
                        className={`relative h-6 w-11 rounded-full transition-colors ${
                          rule.enabled ? "bg-accent-cyan" : "bg-base-500"
                        }`}
                        aria-label={`Toggle ${rule.rule_name}`}
                      >
                        <span
                          className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-transform ${
                            rule.enabled ? "left-5" : "left-0.5"
                          }`}
                        />
                      </button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
