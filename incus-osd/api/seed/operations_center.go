package seed

// OperationsCenter represents an Operations Center seed file.
type OperationsCenter struct {
	// PEM-encoded server and/or client TLS certificates. If not specified, certificates will
	// be auto-generated when Operations Center first starts up.
	ServerCertificate string `json:"server_certificate,omitempty" yaml:"server_certificate,omitempty"`
	ServerKey         string `json:"server_key,omitempty"         yaml:"server_key,omitempty"`
	ClientCertificate string `json:"client_certificate,omitempty" yaml:"client_certificate,omitempty"`
	ClientKey         string `json:"client_key,omitempty"         yaml:"client_key,omitempty"`

	// An array of SHA256 certificate fingerprints that belong to trusted TLS clients.
	TrustedTLSClientCertFingerprints []string `json:"trusted_tls_client_cert_fingerprints,omitempty" yaml:"trusted_tls_client_cert_fingerprints,omitempty"`
}
