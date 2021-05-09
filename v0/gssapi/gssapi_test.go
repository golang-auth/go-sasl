package gssapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMsgSize(t *testing.T) {
	var tests = []struct {
		data []byte
		size uint32
	}{
		{[]byte{0, 0, 0, 0}, 0},
		{[]byte{1, 0, 0, 0}, 0},
		{[]byte{0, 0, 0, 1}, 1},
		{[]byte{0, 0, 1, 0}, 256},
		{[]byte{0, 1, 0, 0}, 65536},
		{[]byte{1, 1, 0, 0}, 65536},
		{[]byte{1, 1, 1, 1}, 65793},
		{[]byte{1, 255, 0, 0}, 65536 * 255},
		{[]byte{1, 255, 255, 255}, 65536*255 + 256*255 + 255},
	}

	for _, tt := range tests {
		sz := uint32(tt.data[1])<<16 | uint32(tt.data[2])<<8 + uint32(tt.data[3])
		assert.Equal(t, tt.size, sz)
	}
}
