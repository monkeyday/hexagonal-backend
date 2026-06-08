package jwt

// Config holds the parameters required to initialise the JWT service.
// Defined here so infrastructure/jwt does not import a cmd/ package.
type Config struct {
	PrivateKeyPath string `validate:"required"`
	PublicKeyPath  string `validate:"required"`
	Issuer         string `validate:"required,url"`
	Kid            string `validate:"required"`
}
