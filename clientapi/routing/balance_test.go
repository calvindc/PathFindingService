package routing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"testing"
	"github.com/ethereum/go-ethereum/common"
	"encoding/binary"
	"github.com/SmartMeshFoundation/SmartRaiden/utils"
	"github.com/SmartMeshFoundation/SmartRaiden/accounts"
	"github.com/ethereum/go-ethereum/crypto"
)

type balanceProof struct {
	Nonce             uint64      `json:"nonce"`
	TransferAmount    *big.Int    `json:"transfer_amount"`
	LocksRoot         common.Hash `json:"locks_root"`
	ChannelIdentifier common.Hash `json:"channel_identifier"`
	OpenBlockNumber   int64       `json:"open_block_number"`
	MessageHash       common.Hash `json:"addition_hash"`
	//signature is nonce + transferred_amount + locksroot + channel_identifier + message_hash
	Signature []byte `json:"signature"`
}

type ProofForPFS struct {
	BalanceProof balanceProof `json:"balance_proof"`
	Signature    []byte       `json:"balance_signature"`
	LockAmount   *big.Int     `json:"lock_amount"`
}

func TestUpdateBalanceProof(t *testing.T) {
	nonce := uint64(2)
	transferAmount := big.NewInt(100)
	locksRoot := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000")
	channelID := common.HexToHash("0x0398beea63f098e2d3bb59884be79eda00cf042e39ad65e5c43a0a280f969f93")
	openBlockNumber := int64(12)
	additionalHash := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000")
	lockAmount := big.NewInt(0)
	keyPath:="/home/cy/.ethereum/keystore"
	balancePeerAddress:="0xc67f23ce04ca5e8dd9f2e1b5ed4fad877f79267a"
	messagePeerAddress:="0xd4bd8facd16704c2b6ed4b06775467d44f216174"
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, nonce)          //nonce
	_, err = buf.Write(utils.BigIntTo32Bytes(transferAmount))  //transfer_amount
	_, err = buf.Write(locksRoot[:])                           //locksroot
	_, err = buf.Write(channelID[:])                           //channel_id
	err = binary.Write(buf, binary.BigEndian, openBlockNumber) //open_block_number
	_, err = buf.Write(additionalHash[:])                      //additional_hash

	//=========================================
	tmpBuf := new(bytes.Buffer)
	_, err = tmpBuf.Write([]byte("\x19Ethereum Signed Message:\n")) //ContractSignaturePrefix
	_, err = tmpBuf.Write([]byte("176"))                            //ContractBalanceProofMessageLength
	_, err = tmpBuf.Write(utils.BigIntTo32Bytes(transferAmount))    //TransferAmount
	_, err = tmpBuf.Write(locksRoot[:])                             //LocksRoot
	err = binary.Write(tmpBuf, binary.BigEndian, 1)            //Nonce
	_, err = tmpBuf.Write(additionalHash[:])                        //AdditionalHash
	_, err = tmpBuf.Write(channelID[:])                             //ChannelID
	err = binary.Write(tmpBuf, binary.BigEndian, openBlockNumber)   //OpenBlockNumber
	_, err = tmpBuf.Write(utils.BigIntTo32Bytes(big.NewInt(8888)))  //ChainID
	accmanager := accounts.NewAccountManager(keyPath)
	privkeybin, err := accmanager.GetPrivateKey(common.HexToAddress(balancePeerAddress), "123")
	if err!=nil{
		t.Error(err)
	}

	privateKey, err := crypto.ToECDSA(privkeybin)
	if err != nil {
		t.Error(err)
	}
	balancesignature, err := utils.SignData(privateKey, tmpBuf.Bytes())
	if err != nil {
		t.Error(err)
	}
	//=========================================
	_, err = buf.Write(balancesignature)
	privkeybin1, err := accmanager.GetPrivateKey(common.HexToAddress(messagePeerAddress), "123")
	if err!=nil{
		t.Error(err)
	}

	privateKey1, err := crypto.ToECDSA(privkeybin1)
	if err != nil {
		t.Error(err)
	}
	messagesignature, err := utils.SignData(privateKey1, tmpBuf.Bytes())
	if err != nil {
		t.Error(err)
	}
	_, err = buf.Write(utils.BigIntTo32Bytes(lockAmount)) //locks_amount

	bp:=&balanceProof{
		Nonce:nonce,
		TransferAmount:transferAmount,
		LocksRoot:locksRoot,
		ChannelIdentifier:channelID,
		OpenBlockNumber:openBlockNumber,
		MessageHash:additionalHash,
		Signature:balancesignature,
	}
	bpr := &ProofForPFS{
		BalanceProof: *bp,
		Signature:    messagesignature,
		LockAmount:   lockAmount,
	}

	var respBody interface{}
	respBody,err=MakeRequest1("PUT",*bpr,nil)
	if err!=nil{
		t.Error(err)
	}
	t.Log(respBody)

}

func MakeRequest1(method string, reqBody interface{}, resBody interface{}) ([]byte, error) {
	httpurl := "http://localhost:9001/pathfinder/0xc67f23CE04ca5E8DD9f2E1B5eD4FaD877f79267A/balance"
	var req *http.Request
	var errh error
	httpclient := http.DefaultClient
	if reqBody != nil {
		var jsonStr []byte
		jsonStr, errh = json.Marshal(reqBody)
		if errh != nil {
			fmt.Println(fmt.Sprintf("Marshal json error: %s", errh))
		}
		req, errh = http.NewRequest("PUT", httpurl, bytes.NewBuffer(jsonStr))
		if errh != nil {
			fmt.Println(fmt.Sprintf("error: %s", errh))
		}
	} else {
		req, errh = http.NewRequest("PUT", httpurl, nil)
		if errh != nil {
			fmt.Println(fmt.Sprintf("error: %s", errh))
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "close")
	res, err := httpclient.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		fmt.Println(fmt.Sprintf("error: %s", err))
	}
	contents, err := ioutil.ReadAll(res.Body)
	if res.StatusCode/100!=2 {
		fmt.Println(fmt.Sprintf("UpdateBalanceProof error: %s", err))
	}
	if err!=nil{
		return nil,err
	}
	if resBody != nil {
		if err = json.Unmarshal(contents, &resBody); err != nil {
			return nil, err
		}
	}
	return contents,nil
}
