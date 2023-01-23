package types

import (
	"errors"
	"io"

	"github.com/casper-ecosystem/casper-golang-sdk/keypair"
)

// Signature representing signature
type Signature struct {
	Tag           keypair.KeyTag
	SignatureData []byte
}

func (key Signature) Marshal(w io.Writer) (int, error) {
	n, err := w.Write([]byte{byte(key.Tag)})
	if err != nil {
		return n, err
	}

	n2, err := w.Write(key.SignatureData)
	n += n2

	return n, err
}

func (key *Signature) Unmarshal(data []byte) (int, error) {
	if data[0] == 0x01 {
		key.Tag = keypair.KeyTagEd25519
	} else if data[0] == 0x02 {
		key.Tag = keypair.KeyTagSecp256k1
	} else {
		return 0, errors.New("Unexpected signature prefix")
	}

	key.SignatureData = data[1:]

	return 0, nil
}
