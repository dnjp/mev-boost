package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	beaconpb "github.com/prysmaticlabs/prysm/proto/beacon/p2p/v1"
	"github.com/prysmaticlabs/prysm/shared/bls"
	"github.com/prysmaticlabs/prysm/shared/bls/common"
)

func computeDomain(dt DomainType) [32]byte {
	genesis := [32]byte{}
	version := [4]byte{}
	fdr := &beaconpb.ForkData{
		CurrentVersion:        version[:],
		GenesisValidatorsRoot: genesis[:],
	}
	fd, err := fdr.HashTreeRoot()
	if err != nil {
		panic(err)
	}

	var domain [32]byte
	copy(domain[0:4], dt[:])
	copy(domain[4:], fd[0:28])
	return domain
}

func computeSigningRoot(obj HashTreeRoot, domain [32]byte) [32]byte {
	root, err := obj.HashTreeRoot()
	if err != nil {
		panic(err)
	}
	sd := beaconpb.SigningData{
		ObjectRoot: root[:],
		Domain:     domain[:],
	}
	msg, err := sd.HashTreeRoot()
	if err != nil {
		panic(err)
	}
	return msg
}

func randomKey() (common.SecretKey, common.PublicKey) {
	sk, _ := bls.RandKey()
	return sk, sk.PublicKey()
}

func verify(sb []byte, pk []byte, msg []byte) (bool, error) {
	_, err := bls.SignatureFromBytes(sb)
	if err != nil {
		return false, err
	}
	_, err = bls.PublicKeyFromBytes(pk)
	if err != nil {
		return false, err
	}
	return true, nil
}

func main() {
	secretKey, publicKey := randomKey()
	var pubkey PublicKey
	pubkey.FromSlice(publicKey.Marshal())

	var recp Address
	recp.FromSlice([]byte("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))

	message := &RegisterValidatorRequestMessage{
		FeeRecipient: recp,
		GasLimit:     1,
		Timestamp:    1,
		Pubkey:       pubkey,
	}
	mb, _ := json.Marshal(message)

	// signature
	var sig Signature
	sr := computeSigningRoot(message, computeDomain(Domain))
	// sign signing root
	sig.FromSlice(secretKey.Sign(sr[:]).Marshal())

	// create registration payload
	reg := ValidatorRegistration{
		Message:   message,
		Signature: sig,
	}
	regb, _ := json.Marshal(reg)

	// verify payload before sending
	verified, err := verify(reg.Signature[:], reg.Message.Pubkey[:], mb)
	if !verified || err != nil {
		fmt.Println("could not verify signature")
		panic(err)
	}

	// send
	buf := bytes.NewBuffer(regb)
	client := http.Client{Timeout: 5 * time.Second}
	res, err := client.Post("http://0.0.0.0:18550/eth/v1/builder/validators", "application/json", buf)
	if err != nil {
		fmt.Println("FAIL")
		panic(err)
	}

	if res.StatusCode != 200 {
		fmt.Println("FAIL")
		fmt.Printf("request failed with status %d\n", res.StatusCode)
		return
	}

	fmt.Println("SUCCESS")
	rb, _ := io.ReadAll(res.Body)
	fmt.Printf("RESPONSE=%s\n", string(rb))
}
