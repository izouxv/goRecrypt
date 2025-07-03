package hdkey

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/izouxv/goRecrypt/curve"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKey_SignTx(t *testing.T) {
	// 1. Setup: Get a secp256k1 key
	curve := curve.CurveGet("secp256k1")
	// seed, _ := hex.DecodeString("...some seed...")
	seed := []byte("11111111111111111111")
	accountKey, err := NewMaster(seed, curve)
	require.NoError(t, err)

	// 2. Create a dummy transaction
	toAddress := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	tx := types.NewTransaction(0, toAddress, big.NewInt(10000), 21000, big.NewInt(5000000000), nil)
	chainID := big.NewInt(1) // Mainnet

	// 3. Sign the transaction
	signedTx, err := accountKey.SignTx(tx, chainID)
	require.NoError(t, err)
	require.NotNil(t, signedTx)

	// 4. Verify the signature
	// Use the same signer logic as the implementation to verify the sender.
	// LatestSignerForChainID will select the correct signer based on the chain ID.
	signer := types.LatestSignerForChainID(chainID)
	sender, err := types.Sender(signer, signedTx)
	require.NoError(t, err)

	expectedAddr, err := accountKey.Address()
	require.NoError(t, err)
	assert.Equal(t, common.BytesToAddress(expectedAddr), sender, "The sender recovered from the signature should match the key's address")
}

func TestKey_SignEIP1559Tx(t *testing.T) {
	// 1. Setup: Get a secp256k1 key
	curve := curve.CurveGet("secp256k1")
	seed := []byte("22222222222222222222")
	accountKey, err := NewMaster(seed, curve)
	require.NoError(t, err)

	// 2. Create a dummy EIP-1559 transaction
	toAddress := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	chainID := big.NewInt(1) // Mainnet
	txData := &types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     0,
		GasTipCap: big.NewInt(1000000000),  // 1 Gwei
		GasFeeCap: big.NewInt(20000000000), // 20 Gwei
		Gas:       21000,
		To:        &toAddress,
		Value:     big.NewInt(10000),
		Data:      nil,
	}
	tx := types.NewTx(txData)

	// 3. Sign the transaction
	signedTx, err := accountKey.SignTx(tx, chainID)
	require.NoError(t, err)
	require.NotNil(t, signedTx)

	// 4. Verify the signature
	signer := types.LatestSignerForChainID(chainID)
	sender, err := types.Sender(signer, signedTx)
	require.NoError(t, err)

	expectedAddr, err := accountKey.Address()
	require.NoError(t, err)
	assert.Equal(t, common.BytesToAddress(expectedAddr), sender, "The sender recovered from the signature should match the key's address")
}
