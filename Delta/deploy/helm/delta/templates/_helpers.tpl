{{/* Standard Helm helpers for the Delta chart (D-010). */}}

{{- define "delta.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "delta.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "delta.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "delta.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "delta.labels" -}}
helm.sh/chart: {{ include "delta.chart" . }}
{{ include "delta.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "delta.selectorLabels" -}}
app.kubernetes.io/name: {{ include "delta.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "delta.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "delta.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "delta.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Bundled Postgres service name. */}}
{{- define "delta.postgresFullname" -}}
{{- printf "%s-postgres" (include "delta.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* App env Secret name (external envSecret, else the createEnvSecret-rendered name). */}}
{{- define "delta.envSecretName" -}}
{{- .Values.envSecret | default (printf "%s-env" (include "delta.fullname" .)) -}}
{{- end -}}

{{/*
Bundled-Postgres connection env (parts + password via secretKeyRef so the
plaintext never lands in a pod spec). The entrypoint shim assembles
DATABASE_URL / APP_DATABASE_URL from these. Shared by both the ingest and admin
Deployments, the migrate Job, and both wait-for-migrate inits. External mode
supplies the full URLs via envSecret instead, so this emits nothing.
*/}}
{{- define "delta.pgEnv" -}}
{{- if .Values.postgres.bundled }}
- name: POSTGRES_HOST
  value: {{ include "delta.postgresFullname" . | quote }}
- name: POSTGRES_PORT
  value: "5432"
- name: POSTGRES_USER
  value: {{ .Values.postgres.auth.username | quote }}
- name: POSTGRES_DB
  value: {{ .Values.postgres.auth.database | quote }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgres.auth.existingSecret | default (include "delta.postgresFullname" .) }}
      key: POSTGRES_PASSWORD
{{- end }}
{{- end -}}

{{/*
Non-secret Orchestrator-seam env, shared by BOTH serve Deployments (the admin
app doesn't call the seam, but sharing keeps a single source of truth cheap and
harmless — it just reads env it never touches). DELTA_ORCH_DISTRIBUTION_URL is
NOT sensitive (no credential); ORCH_SERVICE_TOKEN itself comes from envSecret.
*/}}
{{- define "delta.orchestratorEnv" -}}
{{- if .Values.orchestratorDistributionUrl }}
- name: DELTA_ORCH_DISTRIBUTION_URL
  value: {{ .Values.orchestratorDistributionUrl | quote }}
{{- end }}
- name: DELTA_BUDGET_ENGINE_ENABLED
  value: {{ .Values.budgetEngineEnabled | quote }}
- name: DELTA_KILL_SWITCH_ENABLED
  value: {{ .Values.killSwitchEnabled | quote }}
{{- if .Values.killSwitchMaxTxCostCents }}
- name: DELTA_KILL_SWITCH_MAX_TX_COST_CENTS
  value: {{ .Values.killSwitchMaxTxCostCents | quote }}
{{- end }}
{{- end -}}

{{/*
wait-for-postgres initContainer. Uses the bundled Postgres image (has
pg_isready, already pulled) to block until the DB accepts connections.
Bundled-mode only; external endpoints are assumed already up.
*/}}
{{- define "delta.waitForPostgres" -}}
{{- if .Values.postgres.bundled }}
- name: wait-for-postgres
  image: {{ .Values.postgres.image }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  securityContext:
    {{- toYaml .Values.securityContext | nindent 4 }}
  command:
    - sh
    - -c
    - |
      until pg_isready -h {{ include "delta.postgresFullname" . }} -p 5432 -U {{ .Values.postgres.auth.username }} -q; do
        echo "wait-for-postgres: not ready yet"; sleep 2;
      done
      echo "wait-for-postgres: ready"
{{- end }}
{{- end -}}

{{/*
wait-for-migrate initContainer, reused by BOTH the ingest and admin
Deployments. Blocks until the schema is at head by polling `alembic current`
via the entrypoint shim (which assembles DATABASE_URL from pgEnv + envSecret).
Decoupled from the migrate Job object (no RBAC needed) — it observes the
schema STATE the Job produces, so neither serve Deployment races the Job and
no replica of either service starts un-migrated.
*/}}
{{- define "delta.waitForMigrate" -}}
- name: wait-for-migrate
  image: {{ include "delta.image" . }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  securityContext:
    {{- toYaml .Values.securityContext | nindent 4 }}
  command:
    - /usr/local/bin/docker-entrypoint.sh
    - sh
    - -c
    - |
      echo "wait-for-migrate: waiting for schema at head"
      until alembic current 2>/dev/null | grep -q '(head)'; do sleep 3; done
      echo "wait-for-migrate: schema at head"
  env:
    {{- include "delta.pgEnv" . | nindent 4 }}
  {{- if or .Values.envSecret .Values.createEnvSecret }}
  envFrom:
    - secretRef:
        name: {{ include "delta.envSecretName" . }}
  {{- end }}
  volumeMounts:
    - name: tmp
      mountPath: /tmp
{{- end -}}
