package broadlink

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
)

type State struct {
	key []byte
	iv  []byte
}

func NewState() *State {
	ret := State{
		key: []byte{0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02},
		iv:  []byte{0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58},
	}
	return &ret
}

func (state *State) Encrypt(plaintext []byte) []byte {
	block, err := aes.NewCipher(state.key)
	if err != nil {
		log.Fatalln("Failed to create cipher", err)
	}
	mode := cipher.NewCBCEncrypter(block, state.iv)

	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext
}

func (state *State) Decrypt(ciphertext []byte) []byte {
	block, err := aes.NewCipher(state.key)
	if err != nil {
		log.Fatalln("Failed to create cipher", err)
	}
	mode := cipher.NewCBCDecrypter(block, state.iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	return plaintext
}
