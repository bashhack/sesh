package constants

const (
	AWSServicePrefix    = "sesh-aws"
	AWSServiceMFAPrefix = "sesh-aws-serial"
	
	// Constants for web console specific MFA device
	AWSWebConsolePrefix    = "sesh-aws-web"
	AWSWebConsoleMFAPrefix = "sesh-aws-web-serial"

	TOTPServicePrefix = "sesh-totp"
	
	// MetadataServiceName is the single keychain entry name used to store all metadata
	MetadataServiceName = "sesh-metadata"
)
