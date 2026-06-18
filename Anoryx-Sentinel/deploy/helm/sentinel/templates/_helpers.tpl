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
