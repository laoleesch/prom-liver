package auth

// AuthSchema describe all available auth schemes
type AuthSchema struct {
	Header bool             `yaml:"header,omitempty"` //header 'X-Prom-Liver-Id' value
	Basic  AuthSchemaBasic  `yaml:"basic,omitempty"`
	Bearer AuthSchemaBearer `yaml:"bearer,omitempty"`
}

type AuthSchemaBasic struct {
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"password,omitempty"`
	// TODO: Base64   string `yaml:"base64,omitempty"`
	// TODO: File string `yaml:"file,omitempty"`
}

type AuthSchemaBearer struct {
	Token string `yaml:"token,omitempty"`
	// TODO: File  string `yaml:"file,omitempty"`
}
