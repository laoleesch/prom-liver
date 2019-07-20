package auth

// Schema describe all available auth schemes
type Schema struct {
	Header bool         `yaml:"header,omitempty"` //header 'X-Prom-Liver-Id' value
	Basic  SchemaBasic  `yaml:"basic,omitempty"`
	Bearer SchemaBearer `yaml:"bearer,omitempty"`
}

// SchemaBasic basic yaml
type SchemaBasic struct {
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"password,omitempty"`
	// TODO: Base64   string `yaml:"base64,omitempty"`
	// TODO: File string `yaml:"file,omitempty"`
}

// SchemaBearer bearer yaml
type SchemaBearer struct {
	Tokens []string `yaml:"tokens,omitempty"`
	// TODO: Files  []string `yaml:"files,omitempty"`
}
