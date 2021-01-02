package api_test

import (
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
)

func TestRSAKey(t *testing.T) {
	rk := keys.NewRSAKey(test2048RSAKey)
	key := api.NewKey(rk)

	require.Equal(t, keys.ID("rsa1lg8lhzpatgmakvrkz866fehw64lkdtly3t2q7d36kfyhmaauyg2sgkhan4"), key.ID)
	require.Equal(t, rk.Private(), key.Private)
	require.Equal(t, rk.Public(), key.Public)
	require.Equal(t, "rsa", key.Type)

	require.Equal(t, rk, key.AsRSA())
}

func TestRSAMarshal(t *testing.T) {
	clock := tsutil.NewTestClock()

	rk := keys.NewRSAKey(test2048RSAKey)
	key := api.NewKey(rk)
	key.Notes = "some test notes"
	key.CreatedAt = clock.NowMillis()
	key.UpdatedAt = clock.NowMillis()

	b, err := msgpack.Marshal(key)
	require.NoError(t, err)
	expected := testdata(t, "testdata/rsa.msgpack")

	require.Equal(t, string(expected), spew.Sdump(b))

	b, err = json.MarshalIndent(key, "", "  ")
	require.NoError(t, err)
	expected = testdata(t, "testdata/rsa.json")
	require.NoError(t, err)
	require.Equal(t, string(expected), string(b))
}

func TestRSAMarshalPublic(t *testing.T) {
	clock := tsutil.NewTestClock()

	rk := keys.NewRSAKey(test2048RSAKey)
	key := api.NewKey(rk.PublicKey())
	key.Notes = "some test notes"
	key.CreatedAt = clock.NowMillis()
	key.UpdatedAt = clock.NowMillis()

	b, err := msgpack.Marshal(key)
	require.NoError(t, err)
	expected := `([]uint8) (len=399 cap=647) {
 00000000  86 a2 69 64 d9 3e 72 73  61 31 6c 67 38 6c 68 7a  |..id.>rsa1lg8lhz|
 00000010  70 61 74 67 6d 61 6b 76  72 6b 7a 38 36 36 66 65  |patgmakvrkz866fe|
 00000020  68 77 36 34 6c 6b 64 74  6c 79 33 74 32 71 37 64  |hw64lkdtly3t2q7d|
 00000030  33 36 6b 66 79 68 6d 61  61 75 79 67 32 73 67 6b  |36kfyhmaauyg2sgk|
 00000040  68 61 6e 34 a4 74 79 70  65 a3 72 73 61 a3 70 75  |han4.type.rsa.pu|
 00000050  62 c5 01 0b 30 82 01 07  02 82 01 00 71 63 c8 42  |b...0.......qc.B|
 00000060  b2 19 0a 89 70 94 2b 27  64 ae d4 2d 41 24 64 7b  |....p.+'d..-A$d{|
 00000070  6f 30 e0 9a 2d a1 c0 e2  56 aa 2e e2 4e 79 0c 40  |o0..-...V...Ny.@|
 00000080  c9 6a 4b d6 6d 75 c3 71  a9 15 e0 70 3c 47 6b 4e  |.jK.mu.q...p<GkN|
 00000090  1a 06 f1 bd 38 c5 a3 c1  0a e3 bd 30 f4 ef 62 a5  |....8......0..b.|
 000000a0  aa 4f 51 2a d1 45 a0 6c  48 e9 64 69 a2 2c e8 e6  |.OQ*.E.lH.di.,..|
 000000b0  21 e0 52 f0 66 9a 8c 34  15 55 12 d8 2e 55 44 7f  |!.R.f..4.U...UD.|
 000000c0  0b 7e 18 da 94 bd 91 1a  c7 b3 aa be 70 68 43 66  |.~..........phCf|
 000000d0  89 64 59 3e e7 1b 2e 5e  48 4b cf 0c 78 34 10 1a  |.dY>...^HK..x4..|
 000000e0  b5 d6 1b ba 1e 63 e6 23  7a f4 04 89 ce 36 a2 60  |.....c.#z....6.` + "`" + `|
 000000f0  da b7 0a dd 4f be c2 4d  65 9d b0 f7 ca c0 99 b0  |....O..Me.......|
 00000100  a3 aa 45 49 ac de 7f c8  58 a7 93 a9 75 e6 cf 65  |..EI....X...u..e|
 00000110  ca 27 6b 74 35 25 f0 88  39 80 f6 ad 06 9b ec 34  |.'kt5%..9......4|
 00000120  6d 78 77 97 38 6d 50 fe  0c 97 34 be 96 7c 7d 84  |mxw.8mP...4..|}.|
 00000130  ae 5b 8f 34 9b 09 40 79  45 7c 0c 0c 6f ee 34 c4  |.[.4..@yE|..o.4.|
 00000140  2a 0b 83 26 03 80 4f 71  e4 9f 33 20 08 16 37 51  |*..&..Oq..3 ..7Q|
 00000150  2c 6c bf 2b b8 1b 6f 6b  e2 39 84 6d 02 01 03 a3  |,l.+..ok.9.m....|
 00000160  63 74 73 d3 00 00 01 1f  71 fb 04 51 a3 75 74 73  |cts.....q..Q.uts|
 00000170  d3 00 00 01 1f 71 fb 04  52 a5 6e 6f 74 65 73 af  |.....q..R.notes.|
 00000180  73 6f 6d 65 20 74 65 73  74 20 6e 6f 74 65 73     |some test notes|
}
`
	require.Equal(t, expected, spew.Sdump(b))

	b, err = json.MarshalIndent(key, "", "  ")
	require.NoError(t, err)
	expected = `{
  "id": "rsa1lg8lhzpatgmakvrkz866fehw64lkdtly3t2q7d36kfyhmaauyg2sgkhan4",
  "type": "rsa",
  "pub": "MIIBBwKCAQBxY8hCshkKiXCUKydkrtQtQSRke28w4JotocDiVqou4k55DEDJakvWbXXDcakV4HA8R2tOGgbxvTjFo8EK470w9O9ipapPUSrRRaBsSOlkaaIs6OYh4FLwZpqMNBVVEtguVUR/C34Y2pS9kRrHs6q+cGhDZolkWT7nGy5eSEvPDHg0EBq11hu6HmPmI3r0BInONqJg2rcK3U++wk1lnbD3ysCZsKOqRUms3n/IWKeTqXXmz2XKJ2t0NSXwiDmA9q0Gm+w0bXh3lzhtUP4MlzS+lnx9hK5bjzSbCUB5RXwMDG/uNMQqC4MmA4BPceSfMyAIFjdRLGy/K7gbb2viOYRtAgED",
  "cts": 1234567890001,
  "uts": 1234567890002,
  "notes": "some test notes"
}`
	require.Equal(t, expected, string(b))
}

func fromBase10(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 10)
	if !ok {
		panic("bad number: " + base10)
	}
	return i
}

var test2048RSAKey *rsa.PrivateKey

func init() {
	test2048RSAKey = &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557"),
			E: 3,
		},
		D: fromBase10("9542755287494004433998723259516013739278699355114572217325597900889416163458809501304132487555642811888150937392013824621448709836142886006653296025093941418628992648429798282127303704957273845127141852309016655778568546006839666463451542076964744073572349705538631742281931858219480985907271975884773482372966847639853897890615456605598071088189838676728836833012254065983259638538107719766738032720239892094196108713378822882383694456030043492571063441943847195939549773271694647657549658603365629458610273821292232646334717612674519997533901052790334279661754176490593041941863932308687197618671528035670452762731"),
		Primes: []*big.Int{
			fromBase10("130903255182996722426771613606077755295583329135067340152947172868415809027537376306193179624298874215608270802054347609836776473930072411958753044562214537013874103802006369634761074377213995983876788718033850153719421695468704276694983032644416930879093914927146648402139231293035971427838068945045019075433"),
			fromBase10("109348945610485453577574767652527472924289229538286649661240938988020367005475727988253438647560958573506159449538793540472829815903949343191091817779240101054552748665267574271163617694640513549693841337820602726596756351006149518830932261246698766355347898158548465400674856021497190430791824869615170301029"),
		},
	}
	test2048RSAKey.Precompute()
}
