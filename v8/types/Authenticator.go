// Package types provides Kerberos 5 data types.
package types

import (
	"crypto/rand"
	goasn1 "encoding/asn1"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/cobraqxx/gokrb5/v8/asn1tools"
	"github.com/cobraqxx/gokrb5/v8/iana"
	"github.com/cobraqxx/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gofork/encoding/asn1"
	"golang.org/x/sys/windows"
)

// Authenticator - A record containing information that can be shown to have been recently generated using the session
// key known only by the client and server.
// https://tools.ietf.org/html/rfc4120#section-5.5.1
type Authenticator struct {
	AVNO              int               `asn1:"explicit,tag:0"`
	CRealm            string            `asn1:"generalstring,explicit,tag:1"`
	CName             PrincipalName     `asn1:"explicit,tag:2"`
	Cksum             Checksum          `asn1:"explicit,optional,tag:3"`
	Cusec             int               `asn1:"explicit,tag:4"`
	CTime             time.Time         `asn1:"generalized,explicit,tag:5"`
	SubKey            EncryptionKey     `asn1:"explicit,optional,tag:6"`
	SeqNumber         int64             `asn1:"explicit,optional,tag:7"`
	AuthorizationData AuthorizationData `asn1:"explicit,optional,tag:8"`
}

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(realm string, cname PrincipalName) (Authenticator, error) {
	seq, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return Authenticator{}, err
	}
	t := time.Now().UTC()
	return Authenticator{
		AVNO:      iana.PVNO,
		CRealm:    realm,
		CName:     cname,
		Cksum:     Checksum{},
		Cusec:     int((t.UnixNano() / int64(time.Microsecond)) - (t.Unix() * 1e6)),
		CTime:     t,
		SeqNumber: seq.Int64() & 0x3fffffff,
	}, nil
}

// GenerateSeqNumberAndSubKey sets the Authenticator's sequence number and subkey.
func (a *Authenticator) GenerateSeqNumberAndSubKey(keyType int32, keySize int) error {
	seq, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return err
	}
	a.SeqNumber = seq.Int64() & 0x3fffffff
	//Generate subkey value
	sk := make([]byte, keySize, keySize)
	rand.Read(sk)
	a.SubKey = EncryptionKey{
		KeyType:  keyType,
		KeyValue: sk,
	}
	return nil
}

// Unmarshal bytes into the Authenticator.
func (a *Authenticator) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, a, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.Authenticator))
	return err
}

// Marshal the Authenticator.
func (a *Authenticator) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*a)
	if err != nil {
		return nil, err
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.Authenticator)
	return b, nil
}

//	PKAuthenticator ::= SEQUENCE {
//		cusec [0] INTEGER (0..999999),
//		ctime [1] KerberosTime,
//		-- cusec and ctime are used as in [RFC4120], for
//		-- replay prevention.
//		nonce [2] INTEGER (0..4294967295),
//		-- Chosen randomly; this nonce does not need to
//		-- match with the nonce in the KDC-REQ-BODY.
//		paChecksum [3] OCTET STRING OPTIONAL,
//		-- MUST be present.
//		-- Contains the SHA1 checksum, performed over
//		-- KDC-REQ-BODY.
//		...
//		}
//
// https://www.rfc-editor.org/rfc/pdfrfc/rfc4556.txt.pdf
type PKAuthenticator struct {
	Cusec int       `asn1:"explicit,tag:0"`
	CTime time.Time `asn1:"generalized,explicit,tag:1"`
	nonce uint32    `asn1:"explicit,tag:2"`
	Cksum []byte    `asn1:"explicit,optional,tag:3"`
}

// NewAuthenticator creates a new PKAuthenticator.
func NewPKAuthenticator() (PKAuthenticator, error) {
	seq, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return PKAuthenticator{}, err
	}
	t := time.Now().UTC()
	return PKAuthenticator{
		Cusec: int((t.UnixNano() / int64(time.Microsecond)) - (t.Unix() * 1e6)),
		CTime: t,
		nonce: uint32(seq.Int64()),
		Cksum: []byte{0},
	}, nil
}

//	AuthPack ::= SEQUENCE {
//		pkAuthenticator [0] PKAuthenticator,
//		clientPublicValue [1] SubjectPublicKeyInfo OPTIONAL,
//		-- Type SubjectPublicKeyInfo is defined in
//		-- [RFC3280].
//		-- Specifies Diffie-Hellman domain parameters
//		-- and the client’s public key value [IEEE1363].
//	   Zhu & Tung Standards Track [Page 10]
//	   RFC 4556 PKINIT June 2006
//		-- The DH public key value is encoded as a BIT
//		-- STRING according to [RFC3279].
//		-- This field is present only if the client wishes
//		-- to use the Diffie-Hellman key agreement method.
//		supportedCMSTypes [2] SEQUENCE OF AlgorithmIdentifier
//		OPTIONAL,
//		-- Type AlgorithmIdentifier is defined in
//		-- [RFC3280].
//		-- List of CMS algorithm [RFC3370] identifiers
//		-- that identify key transport algorithms, or
//		-- content encryption algorithms, or signature
//		-- algorithms supported by the client in order of
//		-- (decreasing) preference.
//		clientDHNonce [3] DHNonce OPTIONAL,
//		-- Present only if the client indicates that it
//		-- wishes to reuse DH keys or to allow the KDC to
//		-- do so (see Section 3.2.3.1).
//		...
//		}
//
// https://www.rfc-editor.org/rfc/pdfrfc/rfc4556.txt.pdf
type AuthPack struct {
	authentificator PKAuthenticator `asn1:"explicit,tag:0"`
	// TODO
	cert windows.CertPublicKeyInfo `asn1:"optional,explicit,tag:1"`
	// TODO
	//supportedCMSTypes []windows.CryptAlgorithmIdentifier `asn1:"optional,explicit,tag:2"`
	clientDHNonce []byte `asn1:"optional,string,tag:3"`
}

// NewAuthenticator creates a new PKAuthenticator.
func NewAuthPack(pk PKAuthenticator) (AuthPack, error) {
	return AuthPack{
		authentificator: pk,
		clientDHNonce:   []byte{0},
		// TODO
	}, nil
}

// Marshal the AuthPack.
func (a *AuthPack) Marshal() ([]byte, error) {
	pk, err := goasn1.MarshalWithParams(a.authentificator, "context,tag:0")
	if err != nil {
		return nil, err
	}

	c, err := goasn1.MarshalWithParams(a.cert, "context,tag:1")
	if err != nil {
		return nil, err
	}

	dh, err := goasn1.MarshalWithParams(a.clientDHNonce, "context,tag:3")
	if err != nil {
		return nil, err
	}

	ap := append(pk, c...)
	ap = append(ap, dh...)

	ap = asn1tools.AddASNAppTag(ap, asn1.TagSequence)

	return ap, nil
}
