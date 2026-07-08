{{/* Standard Helm helpers for the Orchestrator chart (O-008, ADR-0008). */}}

{{- define "orchestrator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "orchestrator.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "orchestrator.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "orchestrator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "orchestrator.labels" -}}
helm.sh/chart: {{ include "orchestrator.chart" . }}
{{ include "orchestrator.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "orchestrator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "orchestrator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "orchestrator.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "orchestrator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "orchestrator.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Bundled Postgres service name. */}}
{{- define "orchestrator.postgresFullname" -}}
{{- printf "%s-postgres" (include "orchestrator.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* App env Secret name (external envSecret, else the createEnvSecret-rendered name). */}}
{{- define "orchestrator.envSecretName" -}}
{{- .Values.envSecret | default (printf "%s-env" (include "orchestrator.fullname" .)) -}}
{{- end -}}

{{/*
Bundled-Postgres connection env (parts + password via secretKeyRef so the
plaintext never lands in a pod spec). The entrypoint shim assembles
ORCH_DATABASE_URL / ORCH_APP_DATABASE_URL from these. Shared by the app and the
migrate Job / wait-for-migrate init. External mode supplies the full URLs via
envSecret instead, so this emits nothing.
*/}}
{{- define "orchestrator.pgEnv" -}}
{{- if .Values.postgres.bundled }}
- name: POSTGRES_HOST
  value: {{ include "orchestrator.postgresFullname" . | quote }}
- name: POSTGRES_PORT
  value: "5432"
- name: POSTGRES_USER
  value: {{ .Values.postgres.auth.username | quote }}
- name: POSTGRES_DB
  value: {{ .Values.postgres.auth.database | quote }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgres.auth.existingSecret | default (include "orchestrator.postgresFullname" .) }}
      key: POSTGRES_PASSWORD
{{- end }}
{{- end -}}

{{/*
wait-for-postgres initContainer. Uses the bundled Postgres image (has
pg_isready, already pulled) to block until the DB accepts connections.
Bundled-mode only; external endpoints are assumed already up.
*/}}
{{- define "orchestrator.waitForPostgres" -}}
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
      until pg_isready -h {{ include "orchestrator.postgresFullname" . }} -p 5432 -U {{ .Values.postgres.auth.username }} -q; do
        echo "wait-for-postgres: not ready yet"; sleep 2;
      done
      echo "wait-for-postgres: ready"
{{- end }}
{{- end -}}

{{/*
wait-for-migrate initContainer (mirrors ADR-0027 D1 — the serve gate). Blocks
until the schema is at head by polling `alembic current` via the entrypoint
shim (which assembles ORCH_DATABASE_URL from pgEnv + envSecret). Decoupled from
the migrate Job object (no RBAC needed) — it observes the schema STATE the Job
produces, so a multi-replica deployment never races and no serve pod starts
un-migrated.
*/}}
{{- define "orchestrator.waitForMigrate" -}}
- name: wait-for-migrate
  image: {{ include "orchestrator.image" . }}
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
    {{- include "orchestrator.pgEnv" . | nindent 4 }}
  {{- if or .Values.envSecret .Values.createEnvSecret }}
  envFrom:
    - secretRef:
        name: {{ include "orchestrator.envSecretName" . }}
  {{- end }}
  volumeMounts:
    - name: tmp
      mountPath: /tmp
{{- end -}}
