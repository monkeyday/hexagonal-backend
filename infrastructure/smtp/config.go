package smtp

// Config holds the transport parameters for the SMTP relay.
// AppBaseURL and other application-level concerns belong in the calling layer.
type Config struct {
	Host string `validate:"required"`
	Port string `validate:"required"`
	From string `validate:"required"`
}

// Addr returns the host:port dial address.
func (c Config) Addr() string {
	return c.Host + ":" + c.Port
}
