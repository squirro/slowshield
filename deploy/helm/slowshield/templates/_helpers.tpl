{{/* Names */}}
{{- define "slowshield.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "slowshield.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if contains (include "slowshield.name" .) .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "slowshield.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "slowshield.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "slowshield.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: slowshield
{{- end -}}

{{- define "slowshield.selectorLabels" -}}
app.kubernetes.io/name: {{ include "slowshield.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "slowshield.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "slowshield.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* image reference: repository@digest or repository:tag (default appVersion) */}}
{{- define "slowshield.image" -}}
{{- $img := index . 0 -}}{{- $ctx := index . 1 -}}
{{- if $img.digest -}}
{{- printf "%s@%s" $img.repository $img.digest -}}
{{- else -}}
{{- printf "%s:%s" $img.repository (default $ctx.Chart.AppVersion $img.tag) -}}
{{- end -}}
{{- end -}}

{{- define "slowshield.publicUrl" -}}
{{- if .Values.publicUrl -}}
{{- .Values.publicUrl | trimSuffix "/" -}}
{{- else -}}
{{- printf "https://%s" (first .Values.hostnames) -}}
{{- end -}}
{{- end -}}

{{- define "slowshield.githubSecretName" -}}
{{- if .Values.feeds.github.existingSecret -}}
{{- .Values.feeds.github.existingSecret -}}
{{- else if .Values.feeds.github.token -}}
{{- printf "%s-github" (include "slowshield.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* port SlowShield listens on: loopback-only behind the Caddy sidecar, 8080 otherwise */}}
{{- define "slowshield.appBind" -}}
{{- if .Values.caddy.enabled -}}127.0.0.1:8081{{- else -}}0.0.0.0:8080{{- end -}}
{{- end -}}
