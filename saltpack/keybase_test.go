package saltpack_test

import (
	"testing"

	"github.com/keys-pub/keys/saltpack"
	"github.com/stretchr/testify/require"
)

func TestKeybaseMessageNoKey(t *testing.T) {
	msg := `BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiS2n6W4XB3QNEC peK0YLJK3LobCmd gqRoOu9htbeNE4l cgh15YfdlKRoFob Gv3J1mr1FhUvKyU pm9W7ClSTRkJOX9 ig5OOn2RHKIpN20 ybTj8AzWbXBhmD8 y9fXvXmW3FMSnC7 Ara2CtZYt0gsE2o bTTsMhU9hBkTww9 rNTZErpLemI6vX0 ms3GBba8SVigyG9 SL4eGq8pzYJTYw7 U0eshvPZ3ikNfcV Z3wp9PRajDjkOMQ yMdj2NDXZDsBveA A0E1V3At27ZETJr OukyTS0hY4iVYXv qEbD5c80UENFJdl wvM152wLf7LwI4R NY9jkDsrXcaHrIJ I4UT6fkr2xTc0j4 DiMO7m5MNHZNc6q 99yLxq9KaRHhc8t D1k9DTKZWYIWrjc EJVErjMvjbBcoKu GOOPEdXwsHJ6q7W NkMrPVFZrQw8kvX Wop2vh1CZdMEEF7 k8Ekv8SBEosw5kQ G8iRPBp1fi491TZ R7Uf0YqtfBiZogG F3CO1tVWZAh3zVi XbnYtJIoTWCii1f tcbMPHlhlgX2NwW 7VAzUleQCWfikye 8KljVNitmKzmACy gGZMibJeKwo8x5h DuSXFDHJRGzFhEW smQz1U8GpHZ1bfC 4J7N8eQNameSAFG e95qC8eTHimQ6x7 ht5NzQC20VHH8mH 8qDd5uCbaGXPALp rerajB8P8AIuOrq hcy7WrNsIAXfQl5 Smm4EmP3JJgnurK UoYXeqbU2YsdzGZ 1kaVk4RpbOXPKps myeCMRlZhomDYDq MGimdSh41dCMEIz b2Yv4pbjSh4c7GD ESuHHoATzOWpjZu uQk4pjzr09HzbZo Vb3HlHqXyUdvd5E CjEPybUmdfuwaRV nSQSxKdvSORgKZq pOVswK9Y3J2aG9i l5Wmo7X22HMpak5 N2j3weYZYhnPqgX SFZAcuUSeDT5puW UFW3HxRRA08zMeZ . END KEYBASE SALTPACK ENCRYPTED MESSAGE.`

	kr := saltpack.NewKeyring()
	_, _, enc, err := saltpack.Open([]byte(msg), kr)
	require.Equal(t, saltpack.SigncryptEncoding, enc)
	require.EqualError(t, err, "no decryption key found for message")

	msg2 := `BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiPI2uHhOZmDhYo ynRuBAu5CSeHWTY sqCf8KAaFomjzNw j9M5xuCaxL97VRa nXAzIBiyO2gcv7V 4xKnLdJUiH1wYqd wzpflpZpHErQ9PD wnL0HoRq8LleQmr VY4TOtb9a6vMdIW wsRebbTQjYEvEmf mG2eiY0F9vA3WkN Eti2kNud2oFNjWC WzMhxgNEnb7xdX0 RUvXMNS7RhjWwmO pxo8z3zpcuPKslh 7QlWjinDuwLFAzJ z93mv8Fpoydj0LP 1bp4FcHhbqsBroE O7KskRL7QQ1y0nD cEuBcudG13G3woJ jMntM7zdAUejuQR 7PvGVoZnCXEqfvy X6F0rYpob9REIDs XW7fXqQlg13Pukw TeukcNcyshhksxR 4TgQqYwQ2s8Gert VMqKnSzucR2Nx0u WdG4oGKKLnWrBgU 7S47v8DcQwgLlEJ iMouf6gap48ovBQ rXuYbLnpjOe7UEM GIPmtLf58ettgRX SGx9mRwQlUkv1GU z6Wviuwx3syY2Dz 7BlCXKtbC0LgRpT 7g37GjMcCzAIxou yzocJ9x2M3aUN5s 6UnTZkZy3D7bITR q84XJh0qfd2MhjI ipASuygG3z8DtPB 1foWBXfS7ctXkph lqMQ0jV4zc6NBof XlTpx73ABTDvjkF q5hGHgJ6nK0JTAg 9ay6LoKBkWzkqph 77uQozls0t1TuZI l5mdZ7cjtLp48Ya ZwcE261wHlg5AUU 4HhGYqB7pTFI0qX xb8i1FepoQuWhlD 0leM1ezREZax4Xo jrSa6BToOwRAwMy U2dHKMQdAML812D 66vkdTJIWoDT61B z78xGEGL4fN5ijZ dxVNEulmP3GfSmS qhn2DpMSgdB9jYp OjNRl0Srq6YTSL. END KEYBASE SALTPACK ENCRYPTED MESSAGE.`
	_, _, enc, err = saltpack.Open([]byte(msg2), kr)
	require.Equal(t, saltpack.EncryptEncoding, enc)
	require.EqualError(t, err, "no decryption key found for message")
}
