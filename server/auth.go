package server

import (
	"bytes"
	"encoding/binary"
	"crypto/tls"
	. "github.com/siddontang/go-mysql/mysql"
	"github.com/siddontang/go-mysql/packet"
	"errors"
)

type Authenticator interface {
	ValidUser(user string) bool
	Authenticate(user string, password string) bool
}

func (c *Conn) writeInitialHandshake() error {
	capability := CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG |
		CLIENT_CONNECT_WITH_DB | CLIENT_PROTOCOL_41 |
		CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_SSL

	data := make([]byte, 4, 128)

	//min version 10
	data = append(data, 10)

	//server version[00]
	data = append(data, ServerVersion...)
	data = append(data, 0)

	//connection id
	data = append(data, byte(c.connectionID), byte(c.connectionID>>8), byte(c.connectionID>>16), byte(c.connectionID>>24))

	//auth-plugin-data-part-1
	data = append(data, c.salt[0:8]...)

	//filter [00]
	data = append(data, 0)

	//capability flag lower 2 bytes, using default capability here
	data = append(data, byte(capability), byte(capability>>8))

	//charset, utf-8 default
	data = append(data, uint8(DEFAULT_COLLATION_ID))

	//status
	data = append(data, byte(c.status), byte(c.status>>8))

	//below 13 byte may not be used
	//capability flag upper 2 bytes, using default capability here
	data = append(data, byte(capability>>16), byte(capability>>24))

	//filter [0x15], for wireshark dump, value is 0x15
	data = append(data, 0x15)

	//reserved 10 [00]
	data = append(data, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

	//auth-plugin-data-part-2
	data = append(data, c.salt[8:]...)

	//filter [00]
	data = append(data, 0)
	return c.WritePacket(data)
}

func (c *Conn) readHandshakeResponse(password string) error {
	data, err := c.ReadPacket()

	if err != nil {
		return err
	}

	pos := 0

	//capability
	c.capability = binary.LittleEndian.Uint32(data[:4])
	pos += 4

	//skip max packet size
	pos += 4

	//charset, skip, if you want to use another charset, use set names
	//c.collation = CollationId(data[pos])
	pos++

	encrypted := false
	switch c.Conn.Conn.(type) {
	case *tls.Conn:
		encrypted = true
	}

	if (c.capability & CLIENT_SSL > 0) && c.tlsConfig == nil {
		return errors.New("client requested TLS, but no server configuration is present")
	}

	if (c.capability & CLIENT_SSL > 0)  && !encrypted {
		if err != nil {
			msg := "unable to decode keypair"
			return errors.New(msg)
		}

		conn := tls.Server(c.Conn.Conn, c.tlsConfig)
		if err := conn.Handshake(); err != nil {
			return err
		}
		c.Conn = packet.NewConn(conn)
		c.Sequence = 2
		return c.readHandshakeResponse(password)
	}

	// enable buffered IO once optional TLS negotiation is complete
	c.EnableBuffer()

	//skip reserved 23[00]
	pos += 23

	//user name
	user := string(data[pos : pos+bytes.IndexByte(data[pos:], 0)])
	pos += len(user) + 1

	valid := false
	if c.authenticator != nil {
		valid = c.authenticator.ValidUser(user)
	} else if c.user == user {
		valid = true
	}

	if !valid {
		return NewDefaultError(ER_NO_SUCH_USER, user, c.RemoteAddr().String())
	}

	//auth length and auth
	authLen := int(data[pos])
	pos++
	auth := data[pos : pos+authLen]

	valid = false
	if c.authenticator != nil {
		valid = c.authenticator.Authenticate(user,string(auth))
	} else {
		checkAuth := CalcPassword(c.salt, []byte(password))
		if bytes.Equal(auth, checkAuth) {
			valid = true
		}
	}

	if !valid {
		return NewDefaultError(ER_ACCESS_DENIED_ERROR, c.RemoteAddr().String(), c.user, "Yes")
	}

	pos += authLen

	if c.capability|CLIENT_CONNECT_WITH_DB > 0 {
		if len(data[pos:]) == 0 {
			return nil
		}

		db := string(data[pos : pos+bytes.IndexByte(data[pos:], 0)])
		pos += len(db) + 1

		if err = c.h.UseDB(db); err != nil {
			return err
		}
	}

	return nil
}
