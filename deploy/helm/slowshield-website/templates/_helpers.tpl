{{- define "website.name" -}}slowshield-website{{- end -}}
{{- define "website.fullname" -}}{{ .Release.Name }}-slowshield-website{{- end -}}
{{- define "website.labels" -}}
app.kubernetes.io/name: {{ include "website.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "website.selector" -}}
app.kubernetes.io/name: {{ include "website.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "website.image" -}}
{{- if .Values.image.digest -}}{{ .Values.image.repository }}@{{ .Values.image.digest }}{{- else -}}{{ .Values.image.repository }}:{{ .Values.image.tag }}{{- end -}}
{{- end -}}
{{- define "website.altHosts" -}}
{{- $canon := .Values.canonicalHost -}}
{{- $alts := list -}}
{{- range .Values.ingress.hosts }}{{ if ne . $canon }}{{ $alts = append $alts . }}{{ end }}{{ end -}}
{{- join " " $alts -}}
{{- end -}}
