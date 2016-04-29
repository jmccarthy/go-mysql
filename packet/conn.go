package packet

import (
	"bufio"
	"bytes"
	"io"
	"net"

	"github.com/juju/errors"
	. "github.com/siddontang/go-mysql/mysql"
	"fmt"
	"encoding/hex"
)

var (
	DumpPackets bool
	DumpPacketsTo io.Writer
)

/*
	Conn is the base class to handle MySQL protocol.
*/
type Conn struct {
	net.Conn
	br *bufio.Reader
	Sequence uint8
}

func NewConn(conn net.Conn) *Conn {
	c := new(Conn)
	c.Conn = conn
	return c
}

func NewFrom(conn net.Conn, oldConn *Conn) *Conn {
	c := new(Conn)
	c.Conn = conn
	return c
}

func (c *Conn) EnableBuffer() error {
	if c.br != nil {
		// should only be enabled once, after TLS upgrade
		return errors.New("buffer already enabled")
	}
	c.br = bufio.NewReaderSize(c.Conn, 4096)
	return nil
}

func (c *Conn) ReadPacket() ([]byte, error) {
	var buf bytes.Buffer
	if err := c.ReadPacketTo(&buf); err != nil {
		return nil, errors.Trace(err)
	} else {
		if (DumpPackets && DumpPacketsTo != nil) {
			fmt.Fprintf(DumpPacketsTo,"<< Reading sequence #%d:\n", c.Sequence)
			fmt.Fprint(DumpPacketsTo,hex.Dump(buf.Bytes()))
		}
		return buf.Bytes(), nil
	}
}

func (c *Conn) ReadPacketTo(w io.Writer) error {
	header := []byte{0, 0, 0, 0}

	var br io.Reader
	br = c.Conn
	// if buffer is enabled, read from it instead
	if c.br != nil {
		br = c.br
	}

	if _, err := io.ReadFull(br, header); err != nil {
		return ErrBadConn
	}

	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if length < 1 {
		return errors.Errorf("invalid payload length %d", length)
	}

	sequence := uint8(header[3])

	if sequence != c.Sequence {
		return errors.Errorf("invalid sequence %d != %d", sequence, c.Sequence)
	}

	c.Sequence++

	if n, err := io.CopyN(w, br, int64(length)); err != nil {
		return ErrBadConn
	} else if n != int64(length) {
		return ErrBadConn
	} else {
		if length < MaxPayloadLen {
			return nil
		}

		if err := c.ReadPacketTo(w); err != nil {
			return err
		}
	}

	return nil
}

// data already has 4 bytes header
// will modify data inplace
func (c *Conn) WritePacket(data []byte) error {
	length := len(data) - 4

	if (DumpPackets && DumpPacketsTo != nil) {
		fmt.Fprintf(DumpPacketsTo, ">> Writing sequence #%d:\n", c.Sequence)
		fmt.Fprint(DumpPacketsTo, hex.Dump(data))
	}

	for length >= MaxPayloadLen {
		data[0] = 0xff
		data[1] = 0xff
		data[2] = 0xff

		data[3] = c.Sequence

		if n, err := c.Write(data[:4+MaxPayloadLen]); err != nil {
			return ErrBadConn
		} else if n != (4 + MaxPayloadLen) {
			return ErrBadConn
		} else {
			c.Sequence++
			length -= MaxPayloadLen
			data = data[MaxPayloadLen:]
		}
	}

	data[0] = byte(length)
	data[1] = byte(length >> 8)
	data[2] = byte(length >> 16)
	data[3] = c.Sequence

	if n, err := c.Write(data); err != nil {
		return ErrBadConn
	} else if n != len(data) {
		return ErrBadConn
	} else {
		c.Sequence++
		return nil
	}
}

func (c *Conn) ResetSequence() {
	c.Sequence = 0
}

func (c *Conn) Close() error {
	c.Sequence = 0
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}
