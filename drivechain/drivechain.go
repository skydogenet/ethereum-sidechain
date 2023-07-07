package drivechain

/*
#cgo LDFLAGS: ./drivechain/target/debug/libdrivechain_eth.a -ldl -lm
#include "./bindings.h"
*/
import "C"
import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

const THIS_SIDECHAIN = 1

// A publicly known "private key" to the treasury account, that holds 21M BTC.
// There are special consensus rules for this account.
//
// The only transfers from this account that are valid correspond to deposits on
// mainchain or to refunds of earlier withdrawal.
//
// Withdrawals are transfers to this account with special data.
//
// Transfering funds to this account without the special withdrawal data will
// burn the coins. They will never show up on mainchain and there will be no way
// to refund them.
const TREASURY_PRIVATE_KEY = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
const TREASURY_ACCOUNT = "0xc96aaa54e2d44c299564da76e1cd3184a2386b8d"

// There are 10,000,000,000 Wei in one Satoshi
var Satoshi = big.NewInt(10_000_000_000)

// There are 10^8 satoshi in one BTC
// There are 10^18 Wei in one Ether.
//
// So let 1 BTC = 1 "Ether" and 1 satoshi = 10^10 Wei.
//
// So there should be 21 * 10 ^ 6 * 10 ^ 18 = 21 * 10^24 "Wei" in the treasury account.

func Init(dbPath, host string, port uint16, rpcUser, rpcPassword string) {
	privKey, err := crypto.HexToECDSA(TREASURY_PRIVATE_KEY)
	if err != nil {
		panic(fmt.Sprintf("can't get treasury private key: %s", err))
	}
	address := crypto.PubkeyToAddress(*privKey.Public().(*ecdsa.PublicKey))
	actualTreasuryAccount := strings.ToLower(address.Hex())
	if TREASURY_ACCOUNT != actualTreasuryAccount {
		panic(fmt.Sprintf("treasury account: %s != actual treasury account: %s", TREASURY_ACCOUNT))
	}
	cDbPath := C.CString(dbPath)
	cHost := C.CString(host)
	cRpcUser := C.CString(rpcUser)
	cRpcPassword := C.CString(rpcPassword)
	C.init(cDbPath, C.ulong(THIS_SIDECHAIN), cHost, C.ushort(port), cRpcUser, cRpcPassword)
	C.free(unsafe.Pointer(cDbPath))
	C.free(unsafe.Pointer(cRpcUser))
	C.free(unsafe.Pointer(cRpcPassword))
}

func GetMainchainTip() common.Hash {
	var cMainchainTip = C.get_mainchain_tip()
	var mainchainTip = C.GoString(cMainchainTip)
	C.free_string(cMainchainTip)
	return common.HexToHash(mainchainTip)
}

type RawDeposit struct {
	address string
	amount  uint64
}

func getDepositOutputs() []RawDeposit {
	ptrDeposits := C.get_deposit_outputs()
	cDeposits := unsafe.Slice(ptrDeposits.ptr, ptrDeposits.len)
	deposits := make([]RawDeposit, 0, ptrDeposits.len)
	for _, cDeposit := range cDeposits {
		deposit := RawDeposit{
			address: C.GoString(cDeposit.address),
			amount:  uint64(cDeposit.amount),
		}
		deposits = append(deposits, deposit)
	}
	C.free_deposits(ptrDeposits)
	return deposits
}

type Deposit struct {
	Address common.Address
	Amount  *big.Int
}

type Withdrawal struct {
	Address [MainchainAddressLength]C.uchar
	Amount  *big.Int
	Fee     *big.Int
}

type Refund struct {
	Id     common.Hash
	Amount *big.Int
}

func GetDepositOutputs() []Deposit {
	rawDeposits := getDepositOutputs()
	deposits := make([]Deposit, 0, len(rawDeposits))
	for _, rawDeposit := range rawDeposits {
		deposits = append(deposits, Deposit{
			Address: common.HexToAddress(rawDeposit.address),
			Amount:  big.NewInt(int64(rawDeposit.amount)),
		})
	}
	return deposits
}

// common.Hash here is for transaction hashes.
func ConnectBlock(deposits []Deposit, withdrawals map[common.Hash]Withdrawal, refunds []Refund, just_checking bool) bool {
	depositsMemory := C.malloc(C.size_t(len(deposits)) * C.size_t(unsafe.Sizeof(C.Deposit{})))
	depositsSlice := (*[1<<30 - 1]C.Deposit)(depositsMemory)
	for i, deposit := range deposits {
		cDeposit := C.Deposit{
			address: C.CString(strings.ToLower(deposit.Address.String())),
			amount:  C.ulong(deposit.Amount.Uint64()),
		}
		depositsSlice[i] = cDeposit
	}
	cDeposits := C.Deposits{
		ptr: &depositsSlice[0],
		len: C.ulong(len(deposits)),
	}
	withdrawalsMemory := C.malloc(C.size_t(len(withdrawals)) * C.size_t(unsafe.Sizeof(C.Withdrawal{})))
	withdrawalsSlice := (*[1<<30 - 1]C.Withdrawal)(withdrawalsMemory)
	{
		i := 0
		for id, w := range withdrawals {
			log.Info(fmt.Sprintf("wtid = %s", id.Hex()))
			cWithdrawal := C.Withdrawal{
				id:      C.CString(id.Hex()),
				address: w.Address,
				amount:  C.ulong(w.Amount.Uint64()),
				fee:     C.ulong(w.Fee.Uint64()),
			}
			withdrawalsSlice[i] = cWithdrawal
			i += 1
		}
	}
	cWithdrawals := C.Withdrawals{
		ptr: &withdrawalsSlice[0],
		len: C.ulong(len(withdrawals)),
	}
	refundsMemory := C.malloc(C.size_t(len(refunds)) * C.size_t(unsafe.Sizeof(C.Refund{})))
	refundsSlice := (*[1<<30 - 1]C.Refund)(refundsMemory)
	for i, r := range refunds {
		cRefund := C.Refund{
			id:     C.CString(r.Id.Hex()),
			amount: C.ulong(r.Amount.Uint64()),
		}
		refundsSlice[i] = cRefund
	}
	cRefunds := C.Refunds{
		ptr: &refundsSlice[0],
		len: C.ulong(len(refunds)),
	}
	return bool(C.connect_block(cDeposits, cWithdrawals, cRefunds, C.bool(just_checking)))
}

func DisconnectBlock(deposits []Deposit, withdrawals []common.Hash, refunds []common.Hash, just_checking bool) bool {
	depositsMemory := C.malloc(C.size_t(len(deposits)) * C.size_t(unsafe.Sizeof(C.Deposit{})))
	depositsSlice := (*[1<<30 - 1]C.Deposit)(depositsMemory)
	for i, deposit := range deposits {
		cDeposit := C.Deposit{
			address: C.CString(strings.ToLower(deposit.Address.String())),
			amount:  C.ulong(deposit.Amount.Uint64()),
		}
		depositsSlice[i] = cDeposit
	}
	cDeposits := C.Deposits{
		ptr: &depositsSlice[0],
		len: C.ulong(len(deposits)),
	}
	withdrawalsMemory := C.malloc(C.size_t(len(withdrawals)) * C.size_t(unsafe.Sizeof(C.Withdrawal{})))
	withdrawalsSlice := (*[1<<30 - 1]C.Withdrawal)(withdrawalsMemory)
	for i, id := range withdrawals {
		cWithdrawal := C.Withdrawal{
			id: C.CString(id.Hex()),
		}
		withdrawalsSlice[i] = cWithdrawal
	}
	cWithdrawals := C.Withdrawals{
		ptr: &withdrawalsSlice[0],
		len: C.ulong(len(withdrawals)),
	}
	refundsMemory := C.malloc(C.size_t(len(refunds)) * C.size_t(unsafe.Sizeof(C.Refund{})))
	refundsSlice := (*[1<<30 - 1]C.Refund)(refundsMemory)
	for i, id := range refunds {
		cRefund := C.Refund{
			id: C.CString(id.Hex()),
		}
		refundsSlice[i] = cRefund
	}
	cRefunds := C.Refunds{
		ptr: &refundsSlice[0],
		len: C.ulong(len(refunds)),
	}
	return bool(C.disconnect_block(cDeposits, cWithdrawals, cRefunds, C.bool(just_checking)))
}

func FormatDepositAddress(address string) string {
	cAddress := C.CString(address)
	cDepositAddress := C.format_deposit_address(cAddress)
	depositAddress := C.GoString(cDepositAddress)
	C.free(unsafe.Pointer(cAddress))
	C.free_string(cDepositAddress)
	return depositAddress
}

func CreateDeposit(address common.Address, amount uint64, fee uint64) bool {
	cAddress := C.CString(strings.ToLower(address.Hex()))
	cAmount := C.ulong(amount)
	cFee := C.ulong(fee)
	result := C.create_deposit(cAddress, cAmount, cFee)
	C.free(unsafe.Pointer(cAddress))
	return bool(result)
}

const (
	FeeLength              = 8
	MainchainAddressLength = 20
)

func GetWithdrawalData(fee uint64) []byte {
	feeBytes := make([]byte, FeeLength)
	binary.BigEndian.PutUint64(feeBytes, fee)
	addressBytes := make([]byte, MainchainAddressLength)
	cAddress := C.get_new_mainchain_address()
	for i, uchar := range cAddress.address {
		addressBytes[i] = byte(uchar)
	}
	return append(feeBytes, addressBytes...)
}

func DecodeWithdrawal(value *big.Int, data []byte) (Withdrawal, error) {
	if len(data) != FeeLength+MainchainAddressLength {
		return Withdrawal{}, errors.New("wrong withdrawal data length")
	}
	feeBytes := data[:FeeLength]
	if len(feeBytes) != FeeLength {
		panic("off by one error")
	}
	addressBytes := data[FeeLength : FeeLength+MainchainAddressLength]
	if len(addressBytes) != MainchainAddressLength {
		panic("off by one error")
	}
	var address [MainchainAddressLength]C.uchar
	for i, byte := range addressBytes {
		address[i] = C.uchar(byte)
	}
	// Convert Wei to Satoshi.
	var amount big.Int
	amount.Div(value, Satoshi)
	fee := big.NewInt(int64(binary.BigEndian.Uint64(feeBytes)))
	return Withdrawal{
		Address: address,
		Amount:  &amount,
		Fee:     fee,
	}, nil
}

func AttemptBundleBroadcast() bool {
	return bool(C.attempt_bundle_broadcast())
}

func GetUnspentWithdrawals() map[common.Hash]Withdrawal {
	ptrWithdrawals := C.get_unspent_withdrawals()
	cWithdrawals := unsafe.Slice(ptrWithdrawals.ptr, ptrWithdrawals.len)
	withdrawals := make(map[common.Hash]Withdrawal)
	for _, cWithdrawal := range cWithdrawals {
		var amount big.Int
		var fee big.Int
		amount.Mul(big.NewInt(int64(cWithdrawal.amount)), Satoshi)
		fee.Mul(big.NewInt(int64(cWithdrawal.fee)), Satoshi)
		withdrawal := Withdrawal{
			Address: cWithdrawal.address,
			Amount:  &amount,
			Fee:     &fee,
		}
		strId := C.GoString(cWithdrawal.id)
		id := common.HexToHash(strId)
		withdrawals[id] = withdrawal
	}
	C.free_withdrawals(ptrWithdrawals)
	return withdrawals
}

func FormatMainchainAddress(dest [MainchainAddressLength]C.uchar) string {
	withdrawalAddress := C.WithdrawalAddress{address: dest}
	cAddress := C.format_mainchain_address(withdrawalAddress)
	address := C.GoString(cAddress)
	C.free_string(cAddress)
	return address
}

func attemptBmm(criticalHash string, prevMainBlockHash string, amount uint64) {
	cCriticalHash := C.CString(criticalHash)
	cPrevMainBlockHash := C.CString(prevMainBlockHash)
	C.attempt_bmm(cCriticalHash, cPrevMainBlockHash, C.ulong(amount))
	C.free(unsafe.Pointer(cCriticalHash))
	C.free(unsafe.Pointer(cPrevMainBlockHash))
}

func AttemptBmm(header *types.Header, amount uint64) {
	attemptBmm(header.Hash().Hex()[2:], header.PrevMainBlockHash.Hex()[2:], amount)
}

type BmmState uint

const (
	Succeded BmmState = iota
	Failed
	Pending
)

func ConfirmBmm() BmmState {
	return BmmState(C.confirm_bmm())
}

func verifyBmm(prevMainBlockHash string, criticalHash string) bool {
	cPrevMainBlockHash := C.CString(prevMainBlockHash)
	cCriticalHash := C.CString(criticalHash)
	result := bool(C.verify_bmm(cPrevMainBlockHash, cCriticalHash))
	C.free(unsafe.Pointer(cPrevMainBlockHash))
	C.free(unsafe.Pointer(cCriticalHash))
	return result
}

func VerifyBmm(prevMainBlockHash common.Hash, criticalHash common.Hash) bool {
	return verifyBmm(prevMainBlockHash.Hex()[2:], criticalHash.Hex()[2:])
}

func IsWithdrawalSpent(id common.Hash) bool {
	cId := C.CString(id.Hex())
	result := bool(C.is_outpoint_spent(cId))
	C.free(unsafe.Pointer(cId))
	return result
}
