package utils

import (
	"encoding/binary"
	"io"
)

type readByte struct {
	in   io.Reader
	read int
}

func (s *readByte) ReadByte() (byte, error) {
	var data [1]byte
	_, err := s.in.Read(data[:])
	s.read++
	return data[0], err
}

func ReadVarInt(sr io.Reader) (num int64, n int64, err error) {
	rb := &readByte{in: sr}
	nn, err := binary.ReadVarint(rb)
	return int64(nn), int64(rb.read), err
}

func ReadVarBytes(r io.Reader) (data []byte, varIntLen int, err error) {
	num, n, err := ReadVarInt(r)
	if err != nil {
		return nil, 0, err
	}
	varIntLen = int(n)
	data = make([]byte, num)
	_, err = io.ReadFull(r, data)
	return data, varIntLen, err
}

func writeVarNum(num int64, buf []byte) (data []byte) {
	if len(buf) < 9 {
		buf = make([]byte, 9)
	}
	n := binary.PutVarint(buf, num)
	data = buf[:n]
	return
}

func WriteVarBytes(w io.Writer, data []byte) error {
	WriteVarInt(w, int64(len(data)))
	w.Write(data)
	return nil
}

func WriteVarInt(w io.Writer, num int64) error {
	numStr := writeVarNum(num, nil)
	w.Write(numStr)
	return nil
}
