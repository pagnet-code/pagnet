{{- define "pagnet-client.name" -}}
{{- printf "%s-pagnet-client" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "pagnet-client.labels" -}}
app.kubernetes.io/name: pagnet-client
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}
{{- define "pagnet-client.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end -}}
