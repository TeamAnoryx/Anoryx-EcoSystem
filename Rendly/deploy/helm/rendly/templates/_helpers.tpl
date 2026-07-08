{{/* Standard Helm helpers for the Rendly chart (R-010, ADR-0010). */}}

{{- define "rendly.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "rendly.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "rendly.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "rendly.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "rendly.labels" -}}
helm.sh/chart: {{ include "rendly.chart" . }}
{{ include "rendly.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "rendly.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rendly.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "rendly.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "rendly.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "rendly.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Bundled Postgres service name. */}}
{{- define "rendly.postgresFullname" -}}
{{- printf "%s-postgres" (include "rendly.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* App env Secret name (external envSecret, else the createEnvSecret-rendered name). */}}
{{- define "rendly.envSecretName" -}}
{{- .Values.envSecret | default (printf "%s-env" (include "rendly.fullname" .)) -}}
{{- end -}}

{{/*
Bundled-Postgres connection env (parts + password via secretKeyRef so the plaintext never
lands in a pod spec). The entrypoint shim assembles DATABASE_URL / APP_DATABASE_URL from
these. Shared by the app and the migrate Job / wait-for-migrate init. External mode
supplies the full URLs via envSecret instead, so this emits nothing.
*/}}
{{- define "rendly.pgEnv" -}}
{{- if .Values.postgres.bundled }}
- name: POSTGRES_HOST
  value: {{ include "rendly.postgresFullname" . | quote }}
- name: POSTGRES_PORT
  value: "5432"
- name: POSTGRES_USER
  value: {{ .Values.postgres.auth.username | quote }}
- name: POSTGRES_DB
  value: {{ .Values.postgres.auth.database | quote }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgres.auth.existingSecret | default (include "rendly.postgresFullname" .) }}
      key: POSTGRES_PASSWORD
{{- end }}
{{- end -}}

{{/*
wait-for-postgres initContainer. Uses the bundled Postgres image (has pg_isready, already
pulled) to block until the DB accepts connections. Bundled-mode only; external endpoints are
assumed already up.
*/}}
{{- define "rendly.waitForPostgres" -}}
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
      until pg_isready -h {{ include "rendly.postgresFullname" . }} -p 5432 -U {{ .Values.postgres.auth.username }} -q; do
        echo "wait-for-postgres: not ready yet"; sleep 2;
      done
      echo "wait-for-postgres: ready"
{{- end }}
{{- end -}}

{{/*
wait-for-migrate initContainer (mirrors Orchestrator ADR-0008 Fork F / Sentinel ADR-0027
D1 — the serve gate). Blocks until the schema is at head by polling `alembic current` via
the entrypoint shim (which assembles DATABASE_URL from pgEnv + envSecret). Decoupled from the
migrate Job object (no RBAC needed) — it observes the schema STATE the Job produces, so a
multi-replica deployment never races and no serve pod starts un-migrated.
*/}}
{{- define "rendly.waitForMigrate" -}}
- name: wait-for-migrate
  image: {{ include "rendly.image" . }}
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
    {{- include "rendly.pgEnv" . | nindent 4 }}
  {{- if or .Values.envSecret .Values.createEnvSecret }}
  envFrom:
    - secretRef:
        name: {{ include "rendly.envSecretName" . }}
  {{- end }}
  volumeMounts:
    - name: tmp
      mountPath: /tmp
{{- end -}}
