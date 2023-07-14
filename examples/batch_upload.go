package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/bnb-chain/greenfield-go-sdk/client"
	"github.com/bnb-chain/greenfield-go-sdk/types"
	types2 "github.com/bnb-chain/greenfield/sdk/types"
	storageTestUtil "github.com/bnb-chain/greenfield/testutil/storage"
	gnfdTypes "github.com/bnb-chain/greenfield/types"
	permTypes "github.com/bnb-chain/greenfield/x/permission/types"
	storageTypes "github.com/bnb-chain/greenfield/x/storage/types"
	"github.com/cometbft/cometbft/crypto/tmhash"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	"log"
)

const privateKeyLength = 32

//	 Flows:
//	 1. User has the primary account primaryAccount.
//	 2. User uses primaryAccount to create a bucket.
//	 3. User uses primaryAccount to sign a payload(decided by user), signature will be used to generate the temporary account's private key.
//	 4. User use primaryAccount to send a tx including below 2 types of msg:
//			a. Grant temporaryAccount CreateObject permission on bucket
//			b. grant temporaryAccount allowance so that gas fee will be deducted from primaryAccount, and primaryAccount is still the new created objects owner.
func main() {
	userAccount, err := types.NewAccountFromPrivateKey("userAccount", privateKey)
	if err != nil {
		log.Fatalf("New account from private key error, %v", err)
	}
	cli, err := client.New(chainId, rpcAddr, client.Option{DefaultAccount: userAccount})
	if err != nil {
		log.Fatalf("unable to new greenfield client, %v", err)
	}
	ctx := context.Background()
	// get storage providers list
	spLists, err := cli.ListStorageProviders(ctx, true)
	if err != nil {
		log.Fatalf("fail to list in service sps")
	}
	// choose the first sp to be the primary SP
	primarySP := spLists[0].GetOperatorAddress()

	//the user creates a bucket uses the primary account
	bucketName := storageTestUtil.GenRandomBucketName()
	opts := types.CreateBucketOptions{ChargedQuota: uint64(100)}
	bucketTx, err := cli.CreateBucket(ctx, bucketName, primarySP, opts)
	handleErr(err, "CreateBucket")
	cli.WaitForTx(ctx, bucketTx)
	log.Printf("created bucket %s txHash=%s", bucketName, bucketTx)

	// generate the temp account using user's primary account signing on payload decided by user, here we add the account nonce to be part of sign payload
	acct, _ := cli.GetAccount(ctx, userAccount.GetAddress().String())
	randPayload := fmt.Sprintf("payload%d", acct.GetSequence())
	tempAcct, err := genTemporaryAccount(userAccount, randPayload)
	tempAcctAddr, _ := tempAcct.GetAddress().Marshal()
	log.Printf("tempopary account address is %s", hex.EncodeToString(tempAcctAddr))

	// BasicAllowance, can config spend limit and expiration time
	basicAllowance := feegrant.BasicAllowance{}

	// Only allowing the temporary account to submit a desired tx type, here is
	allowedMsg := make([]string, 0)
	allowedMsg = append(allowedMsg, "/greenfield.storage.MsgCreateObject")
	allowance, _ := feegrant.NewAllowedMsgAllowance(&basicAllowance, allowedMsg)
	msgGrantAllowance, _ := feegrant.NewMsgGrantAllowance(allowance, userAccount.GetAddress(), tempAcct.GetAddress())

	// Put bucket policy so that the temporary account can create objects within this bucket
	statement := &permTypes.Statement{
		Actions: []permTypes.ActionType{permTypes.ACTION_CREATE_OBJECT},
		Effect:  permTypes.EFFECT_ALLOW,
	}
	msgPutPolicy := storageTypes.NewMsgPutPolicy(userAccount.GetAddress(), gnfdTypes.NewBucketGRN(bucketName).String(),
		permTypes.NewPrincipalWithAccount(tempAcct.GetAddress()), []*permTypes.Statement{statement}, nil)

	// broadcast the tx including 2 msg
	tx, err := cli.BroadcastTx(ctx, []sdk.Msg{msgGrantAllowance, msgPutPolicy}, types2.TxOption{})
	handleErr(err, "BroadcastTx")
	log.Printf("txHash=%s", tx.TxResponse.TxHash)
	cli.WaitForTx(ctx, tx.TxResponse.TxHash)

	// create object content
	var buffer bytes.Buffer
	line := `0123456789`
	for i := 0; i < objectSize/10; i++ {
		buffer.WriteString(fmt.Sprintf("%s", line))
	}

	// define the granter address in txOpt
	txOpt := types2.TxOption{FeeGranter: userAccount.GetAddress()}
	cli.SetDefaultAccount(tempAcct)
	txnHash, err := cli.CreateObject(ctx, bucketName, objectName, bytes.NewReader(buffer.Bytes()), types.CreateObjectOptions{TxOpts: &txOpt})
	handleErr(err, "Create object")
	cli.WaitForTx(ctx, txnHash)
	log.Printf("Created object %s, txHash = %s", objectName, txnHash)
}

// genTemporaryAccount generates a temporary account, the signPayload is to be signed by user's own private key, and
// the signature is used to generate the temporary account's private key.
// User can reconvert account with the signPayload at any time
func genTemporaryAccount(acct *types.Account, signPayload string) (*types.Account, error) {
	signBz := []byte(signPayload)
	sig, err := acct.Sign(tmhash.Sum(signBz))
	if err != nil {
		return nil, err
	}
	if len(sig) < privateKeyLength {
		return nil, fmt.Errorf("required signature lenght is no less than %d, cur lenght %d", privateKeyLength, len(sig))
	}
	log.Printf("tempopary account key is %s", hex.EncodeToString(sig[:privateKeyLength]))
	return types.NewAccountFromPrivateKey("temp", hex.EncodeToString(sig[:privateKeyLength]))
}
