package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestSSHPublicKey(t *testing.T) {
	rsa := `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLpB8I4juBPSPPZyIMVfFpohwuyEqZOZ2qbtbbYUeS8Ag8Mk5PqLfYyPA68swf4AIBbY4JGYU3J/I0Lova4rnaqZgYFe93RCNBBTdzyKB9aTgNjYSABIvYgNVgU/gj182zVQ317Gt5OeCp3SBuUfbDp9XEdubjZXNtGO2i0gbKLHFkTB1yfTzezavX2foTK2vMR2lmid8XrQ4TMH1RhPOYumV4Uwq7ss8YMIzy4YcnfIZtO1aTsThGLyQ8r+dVYQalZF+KjwRcI+73iAVn367Q93LB+FH92cr72d38s7bKjL3VFNWkygjUXBUgLr6V8qyvC0eyWx1jCpI63mhFSR0AtjCvwvvr4mVViD8TsqIdx489j38GSSUVw9e9At7KE/Hi5tJnJuKUXtv+1+6ZJXwbXSDacPbcvcGBxBpdCYqhGPBQEUvfKTXkzlpndz4UGv85D+K8gml1CXKn9AyjPUG0d5XzlL6k+uFLIc+X7aZFtHXjdDIOzgNcghbj0PhLM2E= gabe@ok.local`
	_, err := keys.ParseSSHPublicKey(rsa)
	require.EqualError(t, err, "SSH RSA key not currently supported")

	ed := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ4jWl0FmuOcpONIojVzigw30/NppVZjiPvJGbmLKP2P gabe@ok.local`
	key, err := keys.ParseSSHPublicKey(ed)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, keys.ID("kex1nc345hg9nt3eef8rfz3r2uu2psma8umf54tx8z8meyvmnzeglk8s50xu7y"), key.ID())
}

func TestSSHKey(t *testing.T) {
	edpriv := `-----BEGIN OPENSSH PRIVATE KEY-----
	b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
	QyNTUxOQAAACCeI1pdBZrjnKTjSKI1c4oMN9PzaaVWY4j7yRm5iyj9jwAAAJDRmZP80ZmT
	/AAAAAtzc2gtZWQyNTUxOQAAACCeI1pdBZrjnKTjSKI1c4oMN9PzaaVWY4j7yRm5iyj9jw
	AAAED2F09VUc5ig2cF/HpYJQM6Jzin26cDxFGELnR5HRIF3Z4jWl0FmuOcpONIojVzigw3
	0/NppVZjiPvJGbmLKP2PAAAADWdhYmVAb2subG9jYWw=
	-----END OPENSSH PRIVATE KEY-----`
	priv, err := keys.ParseSSHKey([]byte(edpriv), nil, true)
	require.NoError(t, err)
	require.NotNil(t, priv)
	require.Equal(t, keys.ID("kex1nc345hg9nt3eef8rfz3r2uu2psma8umf54tx8z8meyvmnzeglk8s50xu7y"), priv.ID())

	edpriv2 := `-----BEGIN OPENSSH PRIVATE KEY-----
	b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABALoavAb2
	8dIcqlGPi6liV7AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIDERTslBAFkDBcvs
	xfvxDrCZf9ikmkyU/ElRf++wm9MSAAAAkPGjgsYt9GShNkO2ifLOMb6T2VVROP9xzDL8I5
	yiN0ujsWXO8GueOBMqb08XKkZFe/UTjiKqCDjdJ6+i56T/WmKAVC5Jtw6wEcK5aUF3neXk
	3lr1u4TqwOqfU1VHjnA6SynlfePhOqb/LZbtOJrXKBSnw2PUcUN7KuVq9cY61omabqpmme
	+K2j/PXc0mNxIN5A==
	-----END OPENSSH PRIVATE KEY-----`
	_, err = keys.ParseSSHKey([]byte(edpriv2), nil, true)
	require.EqualError(t, err, "failed to parse ssh key: ssh: this private key is passphrase protected")
	priv, err = keys.ParseSSHKey([]byte(edpriv2), []byte("12345"), true)
	require.NoError(t, err)
	require.NotNil(t, priv)
	require.Equal(t, keys.ID("kex1xyg5aj2pqpvsxpwtanzlhugwkzvhlk9ynfxfflzf29l7lvym6vfqswnvq3"), priv.ID())

	rsa := `-----BEGIN OPENSSH PRIVATE KEY-----
	b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
	NhAAAAAwEAAQAAAYEAy6QfCOI7gT0jz2ciDFXxaaIcLshKmTmdqm7W22FHkvAIPDJOT6i3
	2MjwOvLMH+ACAW2OCRmFNyfyNC6L2uK52qmYGBXvd0QjQQU3c8igfWk4DY2EgASL2IDVYF
	P4I9fNs1UN9exreTngqd0gblH2w6fVxHbm42VzbRjtotIGyixxZEwdcn083s2r19n6Eytr
	zEdpZonfF60OEzB9UYTzmLpleFMKu7LPGDCM8uGHJ3yGbTtWk7E4Ri8kPK/nVWEGpWRfio
	8EXCPu94gFZ9+u0PdywfhR/dnK+9nd/LO2yoy91RTVpMoI1FwVIC6+lfKsrwtHslsdYwqS
	Ot5oRUkdALYwr8L76+JlVYg/E7KiHcePPY9/BkklFcPXvQLeyhPx4ubSZybilF7b/tfumS
	V8G10g2nD23L3BgcQaXQmKoRjwUBFL3yk15M5aZ3c+FBr/OQ/ivIJpdQlyp/QMoz1BtHeV
	85S+pPrhSyHPl+2mRbR143QyDs4DXIIW49D4SzNhAAAFiFoCBY5aAgWOAAAAB3NzaC1yc2
	EAAAGBAMukHwjiO4E9I89nIgxV8WmiHC7ISpk5napu1tthR5LwCDwyTk+ot9jI8DryzB/g
	AgFtjgkZhTcn8jQui9riudqpmBgV73dEI0EFN3PIoH1pOA2NhIAEi9iA1WBT+CPXzbNVDf
	Xsa3k54KndIG5R9sOn1cR25uNlc20Y7aLSBsoscWRMHXJ9PN7Nq9fZ+hMra8xHaWaJ3xet
	DhMwfVGE85i6ZXhTCruyzxgwjPLhhyd8hm07VpOxOEYvJDyv51VhBqVkX4qPBFwj7veIBW
	ffrtD3csH4Uf3ZyvvZ3fyztsqMvdUU1aTKCNRcFSAuvpXyrK8LR7JbHWMKkjreaEVJHQC2
	MK/C++viZVWIPxOyoh3Hjz2PfwZJJRXD170C3soT8eLm0mcm4pRe2/7X7pklfBtdINpw9t
	y9wYHEGl0JiqEY8FARS98pNeTOWmd3PhQa/zkP4ryCaXUJcqf0DKM9QbR3lfOUvqT64Ush
	z5ftpkW0deN0Mg7OA1yCFuPQ+EszYQAAAAMBAAEAAAGAX8p3/snMi+KisbElxv+2a6Yh86
	+rx5/elolE8DU2YdwfQ5G2XKpUsNj0iAYmFuhciSdrpMQoceWMfRdYGkKEgmM8dDf9SPD4
	VGGL0B8Tv2p7P4TOSxnYXqNbu9BD7ThaPn1H7+KiO4gKMl0eIEbV+Ps+BwiXW2ghf7Q2NF
	zvbLKzNCbJw00+EOBWcVbL17CZKKJ+5gj8tDpnYIdyq6IKpFEp4gvOBLT7zbko1CdaWCyv
	XzqGYzr96aXLOfDUtMjKbAYN8YG0sEAMxOmHlnFi1HdTd3lJaj3gBYeCuRVGfP5aYf3fCq
	2+vKS1HYppaQgrTgHyLas37ZfCxTOUZCchrw+L+PLTu72rEnbi03/0nSz0J4tZbKWxIFDL
	Ja/JwXsW8mTZZ+zY178dsVP9zFzJvBtaHhHx9BgQ3BY7/OfgfEwdcCj9VcAgtfc/AEjymC
	ZbKKoR3u+nIpe3pQthl9BczY0RbgkgVQcxsrn2+XBVs3v7FER+JMFF+nVU4VxgdmxBAAAA
	wQDAc52QL6H0K6JDy+RC6EXI3EM4FHqu/An7R8HVtfuigkaOD28HozSf49CX5mxhw2Z/N8
	i3yTo+dkf0GeGabaXaN+yMC+kN58mHsbu8ndO6Z/WukTdP5lhHw5lIVY12q7G0e5I6qy5L
	ZAPfIYaIRi9ovzW8HMZUnlay9KjzNaCWNvzgKcOIeIojmHZSmHVnk+EaQf2/A/bmD3ery8
	vicdJbZFyyQ9IUPjISnXIMVXjznlbZNsc37CerGB9mOWQ/BDQAAADBAPepIe5H0LlB57u6
	IerE9MZf4nGx3xv2UJuSLx8zHShFk2fsT6xB5QYB+TbV2+xwBmJwZyCNI9tUwpJBZgLrcz
	8Z78mp4xPLgYuVchQrTfEw/BBJ/qSih6k6qQgfyJdjDTeeNVvRSasbjPqa17g/sRODxzrS
	WJ+VPDvYxudiRyPWizsjBnng2eaIfddtzjaTWppwycsOFrzt86y43DvuHAlkW2i6N96cSd
	Vg/+B1k8+oW6HqxVMGd5bq5Q4BuwadlQAAAMEA0n+Iv/0kzjDxPHuS59I0VFCdHKaA79hu
	bE7sFBPAxwIuHE6dN8UDmXFQE3hAI15oVRCYXCXzvmMh1BMDlxJyES/gPAoLVjv4JkYyY3
	RC9WcH7cx8S7w5ZGpDJbuHycC75mkq1t3g4vO+OM5zyEM/P3pMjr69A4LDFn5XhOahF5QX
	2dn/Hq9xbwsgbY76EgEOKCC4eVSmigMptUkEuv+noPY0tCdesqSOaLwuH4JPWTwLxYJ+5I
	IAQ7g3qLDlwJOdAAAADWdhYmVAb2subG9jYWwBAgMEBQ==
	-----END OPENSSH PRIVATE KEY-----`
	_, err = keys.ParseSSHKey([]byte(rsa), nil, true)
	require.EqualError(t, err, "SSH RSA key not currently supported")
}

func TestSSHEncode(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	ssh, err := alice.EncodeToSSH(nil)
	require.NoError(t, err)
	out, err := keys.ParseSSHKey(ssh, nil, false)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, out.Bytes(), alice.Bytes())

	ssh, err = alice.EncodeToSSH([]byte{})
	require.NoError(t, err)
	out, err = keys.ParseSSHKey(ssh, nil, false)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, out.Bytes(), alice.Bytes())

	ssh, err = alice.EncodeToSSH([]byte("testpassword"))
	require.NoError(t, err)
	_, err = keys.ParseSSHKey(ssh, nil, false)
	require.EqualError(t, err, "failed to parse ssh key: ssh: this private key is passphrase protected")
	out, err = keys.ParseSSHKey(ssh, []byte("testpassword"), false)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, out.Bytes(), alice.Bytes())
}

func TestSSHEncodePublic(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	b := alice.PublicKey().EncodeToSSHAuthorized()
	out, err := keys.ParseSSHPublicKey(string(b))
	require.NoError(t, err)
	require.Equal(t, out.Bytes(), alice.PublicKey().Bytes())
}
