package packet

import (
	"crypto/tls"
	"github.com/siddontang/go/log"
	"crypto/elliptic"
)

var (
	KeyPair tls.Certificate
	DefaultListenConfig *tls.Config
	DefaultDialConfig *tls.Config
)


// cloneTLSConfig returns a shallow clone of the exported
// fields of cfg, ignoring the unexported sync.Once, which
// contains a mutex and must not be copied.
//
// The cfg must not be in active use by tls.Server, or else
// there can still be a race with tls.Server updating SessionTicketKey
// and our copying it, and also a race with the server setting
// SessionTicketsDisabled=false on failure to set the random
// ticket key.
//
// If cfg is nil, a new zero tls.Config is returned.
func CloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return &tls.Config{
		Rand:                     cfg.Rand,
		Time:                     cfg.Time,
		Certificates:             cfg.Certificates,
		NameToCertificate:        cfg.NameToCertificate,
		GetCertificate:           cfg.GetCertificate,
		RootCAs:                  cfg.RootCAs,
		NextProtos:               cfg.NextProtos,
		ServerName:               cfg.ServerName,
		ClientAuth:               cfg.ClientAuth,
		ClientCAs:                cfg.ClientCAs,
		InsecureSkipVerify:       cfg.InsecureSkipVerify,
		CipherSuites:             cfg.CipherSuites,
		PreferServerCipherSuites: cfg.PreferServerCipherSuites,
		SessionTicketsDisabled:   cfg.SessionTicketsDisabled,
		SessionTicketKey:         cfg.SessionTicketKey,
		ClientSessionCache:       cfg.ClientSessionCache,
		MinVersion:               cfg.MinVersion,
		MaxVersion:               cfg.MaxVersion,
		CurvePreferences:         cfg.CurvePreferences,
	}
}

// cloneTLSClientConfig is like cloneTLSConfig but omits
// the fields SessionTicketsDisabled and SessionTicketKey.
// This makes it safe to call cloneTLSClientConfig on a config
// in active use by a server.
func CloneTLSClientConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return &tls.Config{
		Rand:                     cfg.Rand,
		Time:                     cfg.Time,
		Certificates:             cfg.Certificates,
		NameToCertificate:        cfg.NameToCertificate,
		GetCertificate:           cfg.GetCertificate,
		RootCAs:                  cfg.RootCAs,
		NextProtos:               cfg.NextProtos,
		ServerName:               cfg.ServerName,
		ClientAuth:               cfg.ClientAuth,
		ClientCAs:                cfg.ClientCAs,
		InsecureSkipVerify:       cfg.InsecureSkipVerify,
		CipherSuites:             cfg.CipherSuites,
		PreferServerCipherSuites: cfg.PreferServerCipherSuites,
		ClientSessionCache:       cfg.ClientSessionCache,
		MinVersion:               cfg.MinVersion,
		MaxVersion:               cfg.MaxVersion,
		CurvePreferences:         cfg.CurvePreferences,
	}
}

func init() {
	// force initialization: without this, parallel connection handling would
	// occsionally block forever inside elliptic/p256_amd64.go
	elliptic.P256()

	certKeyPair, err := tls.X509KeyPair([]byte(insecureCert), []byte(insecureCertKey))
	if err != nil {
		log.Infof("unable to load default certificate\n")
		return
	}

	KeyPair = certKeyPair
	DefaultDialConfig = &tls.Config {
		InsecureSkipVerify:true,
	}

	DefaultListenConfig = &tls.Config {
		Certificates:[]tls.Certificate{KeyPair},
		ServerName:"localhost",
	}

}

const insecureCert =
`
-----BEGIN CERTIFICATE-----
MIIC+jCCAeKgAwIBAgIRANOhnGSSDULSZS5yZsvuq9UwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNjAzMDQyMDE3NDJaFw0xNzAzMDQyMDE3
NDJaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQCqMa+nd8gPlRmuPU3ns1gT6kCK54EEspq4RxnkMS7MSpspq7cilGDu
bVoWue8BpVkXs6TYvvx3yZ2wm+wRVn4dWM8X96kZ+oRmTV/Bd0xSfn3ZqsHvt0fR
A6eAgtmZTAcC9P3f5u7utHfepMccew8GrBzQaIQHeycqPckmOOycmWC45L/At0Vp
IrPv1KQCZ6dU+sNR28M9zezTTRnfhlb+xt5/RE8lAMTHP/14IUVBCrq+SzlFwO3D
h0GHg3sy1xuVN0ieRUGTIdb5ga8Gu/ilfOrX7wALblkFZg/BSgUH/Ux4aDtMGU1o
/t8OT8cmnmmb+hQ3tlxi3XXZ/3JSjwkTAgMBAAGjSzBJMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAaJFr/HUT9ByoVvkidw1Lj0O/
d5tfEdUmSyQsXn6aN7hog9zMwz4OzpVjj3KVkMRalewwwAwitEXDGq0mSGf/+ADK
Daxnpk9MLR+d860v9Zd8Ap8xoyNcfFlqw3h1XgO02hqKtDLv11vhjj9s+iAQHiZF
To+z9lxtgLddrMyYb06wVQvvGEqWd6+l54r68tJg5qUrSK3fkiEZoL1cY82w2O5P
0XpdSP+Vro3EKhIQ+iu35lgLMypCCDoDY6js9GvY8dMj1Q2Emv6+Mqiwd3eTJiR5
f8WnEolFhq6EHo0j4aQXDh7FJEnMqb0IgnSXaq9fU1L9MYkC2sOeIFdvML/ukw==
-----END CERTIFICATE-----
`

// use for localhost db listener only
const insecureCertKey =
`
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAqjGvp3fID5UZrj1N57NYE+pAiueBBLKauEcZ5DEuzEqbKau3
IpRg7m1aFrnvAaVZF7Ok2L78d8mdsJvsEVZ+HVjPF/epGfqEZk1fwXdMUn592arB
77dH0QOngILZmUwHAvT93+bu7rR33qTHHHsPBqwc0GiEB3snKj3JJjjsnJlguOS/
wLdFaSKz79SkAmenVPrDUdvDPc3s000Z34ZW/sbef0RPJQDExz/9eCFFQQq6vks5
RcDtw4dBh4N7MtcblTdInkVBkyHW+YGvBrv4pXzq1+8AC25ZBWYPwUoFB/1MeGg7
TBlNaP7fDk/HJp5pm/oUN7ZcYt112f9yUo8JEwIDAQABAoIBAH63bbw3j8oiTjOP
y2BXBJ4XTKTfRw1TWaUYsytWfyx14977zee+KAl9e5TuLQjBrnraM0N5t4oMoA7t
mK80AcQh6ldC+zGvd0KgG0p1Y2sMaPFWlPzBLoRtvxoM0qyzkYjfFeLOE1nBHnqz
ntgSu5ZRMUbuelcDl5540DpYKbtRtEXgadN8349XY0Zfje3V8+HKZDAgfgiTEcro
v9tntG9YdBqhql1OgrMpnKZYYS1JBFAKs+F+VeZEV1iuZkKIrD6QMSNv3u46iHkB
F0TvV3DzfReyskkaxcVJGYlBE2wj/z6ZQ7mA394YtSKacA3SDuA8CYrY6pbJfAQ9
n8qNQnkCgYEAyM2CS0AR7CveZZw9ssa4TZFC72eXyE5iq+uh+7mgD//DtwOeXATm
nXKfQ/iJ4yOVt0NzgrD8rRSdpLcyiaJ3uQNttxlD2OvTQTI1Co8ds3g4/w/tJaeh
dSdzrBZjbM8U1MBVe3zhaTr0fd+0h8E/zzX1FX58kf/2vnV8SClgxs0CgYEA2Po+
gLd9DkGPBcOnilviCxBksrUpqyGccTWDIsj7bTNQjXZ8qQZbyVuquwUlAL4vnE2W
NjnYPVKG2FmnT5CT2xg9pxhIkyeIYvwjeOKMRzitO4ljCHBa0psbneVdJm0HfOI3
GEq3Y2qo/najFRZbinFLaJzvPdtVNnEcZwt8T18CgYBswVmLNhU+63eVYuzLsfNK
F53AGkRLuaCZapKdyqiVYbn3ml8fiYv5xIXcA3Vy7uf8jOy34PHJMDw9ZPdbMgJT
0zaOD4H+r6MIUZAGuwKkHD4Kbu7LESJSWF6+2pVY7kNjAxSJQFa5brPSpOGbESBl
Mt0dmhcP4CkceHcqgjanFQKBgFnyYza42f6u7rtVAH8619n+UcBDmaJ3rILBzDr/
VjtOqnX6SHNJT4OJnJ0q5MwKC3KgN0UDdcD2FTBa+iDhrmmFAwnh5zQZj1B5dbsH
L1/W/vlPWt6EtSHZavlpu9PSHuiGXpCTaLKt5KCYTcLQIeKiVMBpTkQ2SHzpJv0Q
pdfBAoGAE2UaGiOhRcs4bsXZxEzuU3EvsHjsVePN0oKRxlNVx0zP/wxAvoLLNXSY
4Dp4n9NRZdxUDa7eJ/TnagCcIE/jgrb5dclEbN7yMokSjv1G8+oBtC51d5eFnJZ6
jUl3cWjK11yFB8tOIhjdeGIpnoIgvuLoDZX0ZYFbf8q1rEIk734=
-----END RSA PRIVATE KEY-----
`