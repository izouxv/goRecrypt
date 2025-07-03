package hdkey

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// SignTx signs an Ethereum transaction.
// It determines the correct signer based on the chain ID and transaction type,
// calculates the transaction hash, and signs it.
func (k *Key) SignTx(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if k.PrivateKey == nil {
		return nil, errors.New("cannot sign transaction with a public-only key")
	}

	// Use the latest signer for the given chain ID. This will support all
	// transaction types (Legacy, EIP-2930, EIP-1559, etc.).
	signer := types.LatestSignerForChainID(chainID)
	txHash := signer.Hash(tx)

	// Sign the hash using the crypto.Sign function which produces a signature
	// in the required [R || S || V] format (with V being 0 or 1).
	// k.Sign() produces an ASN.1 DER signature which is not compatible.
	sig, err := crypto.Sign(txHash.Bytes(), k.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Embed the signature in the transaction.
	// WithSignature will handle the V value adjustment based on the signer.
	return tx.WithSignature(signer, sig)
}
