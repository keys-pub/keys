// +build !windows,!darwin

package upgrade

func KeyringV1(serviceFrom string, serviceTo string, password string) {
	logger.Infof("Keyring upgrade not supported")
	// Not supported
}
