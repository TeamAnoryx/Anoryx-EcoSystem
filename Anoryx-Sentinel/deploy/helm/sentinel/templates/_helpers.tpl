{{/* Standard Helm helpers for the Sentinel chart (F-010, ADR-0012). */}}

{{- define "sentinel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sentinel.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "sentinel.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "sentinel.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sentinel.labels" -}}
helm.sh/chart: {{ include "sentinel.chart" . }}
{{ include "sentinel.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "sentinel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "sentinel.image" -}}
{{- $variant := .Values.image.variant | default "slim" -}}
{{- $tag := .Values.image.tag | default (printf "%s-%s" .Chart.AppVersion $variant) -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "sentinel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "sentinel.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* OTel collector service name (in-cluster OTLP endpoint target). */}}
{{- define "sentinel.otelCollectorFullname" -}}
{{- printf "%s-otel-collector" (include "sentinel.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Bundled Postgres / Redis service names. */}}
{{- define "sentinel.postgresFullname" -}}
{{- printf "%s-postgres" (include "sentinel.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "sentinel.redisFullname" -}}
{{- printf "%s-redis" (include "sentinel.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Worker / frontend / MinIO names (F-010 Part 2, ADR-0027). */}}
{{- define "sentinel.workerFullname" -}}
{{- printf "%s-worker" (include "sentinel.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "sentinel.frontendFullname" -}}
{{- printf "%s-frontend" (include "sentinel.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "sentinel.minioFullname" -}}
{{- printf "%s-minio" (include "sentinel.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* App env Secret name (external envSecret, else the createEnvSecret-rendered name). */}}
{{- define "sentinel.envSecretName" -}}
{{- .Values.envSecret | default (printf "%s-env" (include "sentinel.fullname" .)) -}}
{{- end -}}

{{/* Worker image (separate from the gateway image — bulk extras / boto3). */}}
{{- define "sentinel.workerImage" -}}
{{- $tag := .Values.worker.image.tag | default (printf "%s-bulk" .Chart.AppVersion) -}}
{{- printf "%s:%s" .Values.worker.image.repository $tag -}}
{{- end -}}

{{/* Frontend image (Next.js console). */}}
{{- define "sentinel.frontendImage" -}}
{{- $tag := .Values.frontend.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.frontend.image.repository $tag -}}
{{- end -}}

{{/*
Bundled-Postgres connection env (parts + password via secretKeyRef so the
plaintext never lands in a pod spec). The entrypoint shim assembles
DATABASE_URL / APP_DATABASE_URL from these. Shared by gateway, worker, migrate,
seed, and the wait-for-migrate init (ADR-0027 D1/D3). External mode supplies the
full URLs via envSecret instead, so this emits nothing.
*/}}
{{- define "sentinel.pgEnv" -}}
{{- if .Values.postgres.bundled }}
- name: POSTGRES_HOST
  value: {{ include "sentinel.postgresFullname" . | quote }}
- name: POSTGRES_PORT
  value: "5432"
- name: POSTGRES_USER
  value: {{ .Values.postgres.auth.username | quote }}
- name: POSTGRES_DB
  value: {{ .Values.postgres.auth.database | quote }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgres.auth.existingSecret | default (include "sentinel.postgresFullname" .) }}
      key: POSTGRES_PASSWORD
{{- end }}
{{- end -}}

{{/*
Non-secret bulk-storage (MinIO) config. The access/secret keys are sensitive and
come from the app envSecret (BULK_STORAGE_ACCESS_KEY / BULK_STORAGE_SECRET_KEY);
only the endpoint + bucket are emitted here.
*/}}
{{- define "sentinel.bulkEnv" -}}
{{- if .Values.minio.enabled }}
- name: BULK_STORAGE_ENDPOINT
  value: {{ printf "http://%s:9000" (include "sentinel.minioFullname" .) | quote }}
- name: BULK_STORAGE_BUCKET
  value: {{ .Values.minio.bucket | quote }}
{{- end }}
{{- end -}}

{{/*
MinIO root creds = the bulk-storage access/secret keys, so the bucket the gateway
and worker use is owned by the same credentials (compose: MINIO_ROOT_USER ==
BULK_STORAGE_ACCESS_KEY). Sourced from the app envSecret; falls back to the
minio default only when no Secret is configured (a non-demo / misconfigured install
— NOTES.txt warns).
*/}}
{{- define "sentinel.minioCredsEnv" -}}
{{- if or .Values.envSecret .Values.createEnvSecret }}
- name: MINIO_ROOT_USER
  valueFrom:
    secretKeyRef:
      name: {{ include "sentinel.envSecretName" . }}
      key: BULK_STORAGE_ACCESS_KEY
- name: MINIO_ROOT_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "sentinel.envSecretName" . }}
      key: BULK_STORAGE_SECRET_KEY
{{- else }}
- name: MINIO_ROOT_USER
  value: "minioadmin"
- name: MINIO_ROOT_PASSWORD
  value: "minioadmin"
{{- end }}
{{- end -}}

{{/*
wait-for-postgres initContainer (ADR-0027 D1). Uses the bundled Postgres image
(has pg_isready, already pulled) to block until the DB accepts connections.
Bundled-mode only; external endpoints are assumed already up.
*/}}
{{- define "sentinel.waitForPostgres" -}}
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
      until pg_isready -h {{ include "sentinel.postgresFullname" . }} -p 5432 -U {{ .Values.postgres.auth.username }} -q; do
        echo "wait-for-postgres: not ready yet"; sleep 2;
      done
      echo "wait-for-postgres: ready"
{{- end }}
{{- end -}}

{{/*
wait-for-migrate initContainer (ADR-0027 D1 — the serve/seed gate). Blocks until
the schema is at head by polling `alembic current` via the entrypoint shim (which
assembles DATABASE_URL from pgEnv + envSecret). Decoupled from the migrate Job
object (no RBAC needed) — it observes the schema STATE the Job produces, so a
multi-replica gateway never races and no serve pod starts un-migrated.
*/}}
{{- define "sentinel.waitForMigrate" -}}
- name: wait-for-migrate
  image: {{ include "sentinel.image" . }}
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
    {{- include "sentinel.pgEnv" . | nindent 4 }}
  {{- if or .Values.envSecret .Values.createEnvSecret }}
  envFrom:
    - secretRef:
        name: {{ .Values.envSecret | default (printf "%s-env" (include "sentinel.fullname" .)) }}
  {{- end }}
  volumeMounts:
    - name: tmp
      mountPath: /tmp
{{- end -}}
