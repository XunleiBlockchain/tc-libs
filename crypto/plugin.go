package crypto

type plugin interface {
	GenerateKey() (PrivKey, error)
	GenerateKeyFromSecret([]byte) (PrivKey, error)
}

var (
	cryptos = make(map[string]plugin)
)

type pluginGM struct{}

func (p pluginGM) GenerateKey() (PrivKey, error) {
	return GenPrivKeyGM()
}

func (p pluginGM) GenerateKeyFromSecret(secret []byte) (PrivKey, error) {
	return GenPrivKeyGMFromSecret(secret)
}

type pluginEd25519 struct{}

func (p pluginEd25519) GenerateKey() (PrivKey, error) {
	return GenPrivKeyEd25519()
}

func (p pluginEd25519) GenerateKeyFromSecret(secret []byte) (PrivKey, error) {
	return GenPrivKeyEd25519FromSecret(secret)
}

type pluginSecp256K1 struct{}

func (p pluginSecp256K1) GenerateKey() (PrivKey, error) {
	return GenPrivKeySecp256k1()
}

func (p pluginSecp256K1) GenerateKeyFromSecret(secret []byte) (PrivKey, error) {
	return GenPrivKeySecp256k1FromSecret(secret)
}

func init() {
	cryptos[CryptoTypeGM] = pluginGM{}
	cryptos[CryptoTypeEd25519] = pluginEd25519{}
	cryptos[CryptoTypeSecp256K1] = pluginSecp256K1{}
}
