package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	ssz "github.com/ferranbt/fastssz"
)

var (
	Domain    DomainType = [4]byte{0x00, 0x00, 0x00, 0x01}
	ErrLength            = fmt.Errorf("incorrect byte length")
)

type DomainType [4]byte

type HashTreeRoot interface {
	HashTreeRoot() ([32]byte, error)
}

type PublicKey [48]byte

func (p PublicKey) MarshalText() ([]byte, error) {
	return hexutil.Bytes(p[:]).MarshalText()
}

func (p *PublicKey) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(p[:])
	b.UnmarshalJSON(input)
	if len(b) != 48 {
		return ErrLength
	}
	p.FromSlice(b)
	return nil
}

func (p *PublicKey) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(p[:])
	b.UnmarshalText(input)
	if len(b) != 48 {
		return ErrLength
	}
	p.FromSlice(b)
	return nil

}

func (p PublicKey) String() string {
	return hexutil.Bytes(p[:]).String()
}

func (p *PublicKey) FromSlice(x []byte) {
	copy(p[:], x)
}

type Signature [96]byte

func (s Signature) MarshalText() ([]byte, error) {
	return hexutil.Bytes(s[:]).MarshalText()
}

func (s *Signature) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(s[:])
	err := b.UnmarshalJSON(input)
	if err != nil {
		return err
	}
	if len(b) != 96 {
		return ErrLength
	}
	s.FromSlice(b)
	return nil
}

func (s *Signature) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(s[:])
	err := b.UnmarshalText(input)
	if err != nil {
		return err
	}
	if len(b) != 96 {
		return ErrLength
	}
	s.FromSlice(b)
	return nil
}

func (s Signature) String() string {
	return hexutil.Bytes(s[:]).String()
}

func (s *Signature) FromSlice(x []byte) {
	copy(s[:], x)
}

type Address [20]byte

func (a Address) MarshalText() ([]byte, error) {
	return hexutil.Bytes(a[:]).MarshalText()
}

func (a *Address) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(a[:])
	b.UnmarshalJSON(input)
	if len(b) != 20 {
		return ErrLength
	}
	a.FromSlice(b)
	return nil
}

func (a *Address) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(a[:])
	b.UnmarshalText(input)
	if len(b) != 20 {
		return ErrLength
	}
	a.FromSlice(b)
	return nil

}

func (a Address) String() string {
	return hexutil.Bytes(a[:]).String()
}

func (a *Address) FromSlice(x []byte) {
	copy(a[:], x)
}

type RegisterValidatorRequestMessage struct {
	FeeRecipient Address   `json:"fee_recipient" ssz-size:"20"` // type was Address
	GasLimit     uint64    `json:"gas_limit,string"`
	Timestamp    uint64    `json:"timestamp,string"`
	Pubkey       PublicKey `json:"pubkey" ssz-size:"48"` // type was PublicKey
}

type ValidatorRegistration struct {
	Message   *RegisterValidatorRequestMessage `json:"message"`
	Signature Signature                        `json:"signature"`
}

// MarshalSSZ ssz marshals the RegisterValidatorRequestMessage object
func (r *RegisterValidatorRequestMessage) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(r)
}

// MarshalSSZTo ssz marshals the RegisterValidatorRequestMessage object to a target array
func (r *RegisterValidatorRequestMessage) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'FeeRecipient'
	dst = append(dst, r.FeeRecipient[:]...)

	// Field (1) 'GasLimit'
	dst = ssz.MarshalUint64(dst, r.GasLimit)

	// Field (2) 'Timestamp'
	dst = ssz.MarshalUint64(dst, r.Timestamp)

	// Field (3) 'Pubkey'
	dst = append(dst, r.Pubkey[:]...)

	return
}

// UnmarshalSSZ ssz unmarshals the RegisterValidatorRequestMessage object
func (r *RegisterValidatorRequestMessage) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 84 {
		return ssz.ErrSize
	}

	// Field (0) 'FeeRecipient'
	copy(r.FeeRecipient[:], buf[0:20])

	// Field (1) 'GasLimit'
	r.GasLimit = ssz.UnmarshallUint64(buf[20:28])

	// Field (2) 'Timestamp'
	r.Timestamp = ssz.UnmarshallUint64(buf[28:36])

	// Field (3) 'Pubkey'
	copy(r.Pubkey[:], buf[36:84])

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the RegisterValidatorRequestMessage object
func (r *RegisterValidatorRequestMessage) SizeSSZ() (size int) {
	size = 84
	return
}

// HashTreeRoot ssz hashes the RegisterValidatorRequestMessage object
func (r *RegisterValidatorRequestMessage) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(r)
}

// HashTreeRootWith ssz hashes the RegisterValidatorRequestMessage object with a hasher
func (r *RegisterValidatorRequestMessage) HashTreeRootWith(hh *ssz.Hasher) (err error) {
	indx := hh.Index()

	// Field (0) 'FeeRecipient'
	hh.PutBytes(r.FeeRecipient[:])

	// Field (1) 'GasLimit'
	hh.PutUint64(r.GasLimit)

	// Field (2) 'Timestamp'
	hh.PutUint64(r.Timestamp)

	// Field (3) 'Pubkey'
	hh.PutBytes(r.Pubkey[:])

	hh.Merkleize(indx)
	return
}
