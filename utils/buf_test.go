package utils

import (
	"bytes"
	mathrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRand_buf(t *testing.T) {
	maxLength := 1000
	var vardata = make([]byte, mathrand.Intn(maxLength))
	var varint = int64(mathrand.Intn(maxLength))
	writeBuf := bytes.NewBuffer(nil)
	WriteVarInt(writeBuf, varint)
	WriteVarBytes(writeBuf, vardata)

	readBuf := bytes.NewBuffer(writeBuf.Bytes())
	varintRead, _, err := ReadVarInt(readBuf)
	assert.Nil(t, err)
	assert.Equal(t, varint, varintRead)
	vardataRead, _, err := ReadVarBytes(readBuf)
	assert.Nil(t, err)
	assert.Equal(t, vardata, vardataRead)
}
