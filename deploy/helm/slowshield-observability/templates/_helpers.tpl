{{/* Names (fullname leaves room for the longest component suffix within 63 characters) */}}
{{- define "obs.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "obs.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 52 | trimSuffix "-" -}}
{{- else if contains (include "obs.name" .) .Release.Name -}}
{{- .Release.Name | trunc 52 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "obs.name" .) | trunc 52 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* (list $ "component") */}}
{{- define "obs.componentName" -}}
{{- printf "%s-%s" (include "obs.fullname" (index . 0)) (index . 1) -}}
{{- end -}}

{{/* (list $ "component"); component may be "" for stack-wide objects */}}
{{- define "obs.labels" -}}
{{- $ctx := index . 0 -}}
helm.sh/chart: {{ printf "%s-%s" $ctx.Chart.Name $ctx.Chart.Version | replace "+" "_" }}
{{ include "obs.selectorLabels" . }}
app.kubernetes.io/version: {{ $ctx.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ $ctx.Release.Service }}
app.kubernetes.io/part-of: slowshield
{{- end -}}

{{- define "obs.selectorLabels" -}}
{{- $ctx := index . 0 -}}
app.kubernetes.io/name: {{ include "obs.name" $ctx }}
app.kubernetes.io/instance: {{ $ctx.Release.Name }}
{{- with index . 1 }}
app.kubernetes.io/component: {{ . }}
{{- end }}
{{- end -}}

{{/* repository:tag@digest (the exact string in observability/images.env), or repository:tag */}}
{{- define "obs.image" -}}
{{- if .digest -}}
{{- printf "%s:%s@%s" .repository .tag .digest -}}
{{- else -}}
{{- printf "%s:%s" .repository .tag -}}
{{- end -}}
{{- end -}}

{{- define "obs.slowshieldNamespace" -}}
{{- default .Release.Namespace .Values.slowshieldNamespace -}}
{{- end -}}

{{/*
The shared configs address the backends by their Compose/Podman names; point them at this release's
Services instead. (list $ content)
*/}}
{{- define "obs.rewriteHosts" -}}
{{- $ctx := index . 0 -}}
{{- $out := index . 1 -}}
{{- range $svc, $port := dict "prometheus" "9090" "loki" "3100" "tempo" "3200" -}}
{{- $out = replace (printf "http://%s:%s" $svc $port) (printf "http://%s:%s" (include "obs.componentName" (list $ctx $svc)) $port) $out -}}
{{- end -}}
{{- $out -}}
{{- end -}}

{{/* ConfigMap data for every file under files/<dir>/ (keys are base names) */}}
{{- define "obs.filesConfig" -}}
{{- $ctx := index . 0 -}}
{{- include "obs.rewriteHosts" (list $ctx (($ctx.Files.Glob (printf "files/%s/**" (index . 1))).AsConfig)) -}}
{{- end -}}

{{/* (list $ component-values) */}}
{{- define "obs.podSecurityContext" -}}
{{- $c := index . 1 -}}
runAsNonRoot: true
runAsUser: {{ $c.uid }}
runAsGroup: {{ $c.uid }}
fsGroup: {{ $c.uid }}
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "obs.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop: [ALL]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* Pod-level fields shared by every component. (list $ component) */}}
{{- define "obs.podCommon" -}}
{{- $ctx := index . 0 -}}
enableServiceLinks: false
{{- with $ctx.Values.priorityClassName }}
priorityClassName: {{ . }}
{{- end }}
{{- with $ctx.Values.imagePullSecrets }}
imagePullSecrets: {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $ctx.Values.nodeSelector }}
nodeSelector: {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $ctx.Values.affinity }}
affinity: {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $ctx.Values.tolerations }}
tolerations: {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* Pod template metadata. (list $ component checksum) */}}
{{- define "obs.podMetadata" -}}
{{- $ctx := index . 0 -}}
labels:
  {{- include "obs.selectorLabels" (list $ctx (index . 1)) | nindent 2 }}
  {{- with $ctx.Values.podLabels }}{{ toYaml . | nindent 2 }}{{- end }}
annotations:
  checksum/config: {{ index . 2 | sha256sum }}
  {{- with $ctx.Values.podAnnotations }}{{ toYaml . | nindent 2 }}{{- end }}
{{- end -}}

{{/* Data volume: the component's PVC or, with persistence.enabled=false, an emptyDir. (list $ component) */}}
{{- define "obs.dataVolume" -}}
{{- $ctx := index . 0 -}}
{{- $p := (index $ctx.Values (index . 1)).persistence -}}
- name: data
  {{- if $p.enabled }}
  persistentVolumeClaim:
    claimName: {{ default (include "obs.componentName" (list $ctx (index . 1))) $p.existingClaim }}
  {{- else }}
  emptyDir: {}
  {{- end }}
{{- end -}}

{{- define "obs.grafanaAdminSecret" -}}
{{- default (include "obs.componentName" (list . "grafana")) .Values.grafana.admin.existingSecret -}}
{{- end -}}

{{- define "obs.alertingSecret" -}}
{{- if .Values.alerting.existingSecret -}}
{{- .Values.alerting.existingSecret -}}
{{- else if .Values.alerting.webhookUrl -}}
{{- include "obs.componentName" (list . "alerting") -}}
{{- end -}}
{{- end -}}

{{/* NetworkPolicy peer: a pod of this release. (list $ component) */}}
{{- define "obs.peer" -}}
- podSelector:
    matchLabels: {{- include "obs.selectorLabels" . | nindent 6 }}
{{- end -}}
{{- define "obs.dnsEgress" -}}
- ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
{{- end -}}
