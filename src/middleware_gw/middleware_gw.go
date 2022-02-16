package main
import (
	"log"
	"net"
	"time"
	"flag"
	"bytes"
	"io/ioutil"
	"sort"

	b64 "encoding/base64"
        "encoding/pem"
        "encoding/json"
	"encoding/hex"

	mrand "math/rand"

        "crypto"
        "crypto/rsa"
        "crypto/x509"
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "crypto/sha256"

        "github.com/iotaledger/iota.go/api"
        "github.com/iotaledger/iota.go/converter"
        "github.com/iotaledger/iota.go/trinary"
        "github.com/iotaledger/iota.go/bundle"
	"github.com/iotaledger/iota.go/transaction"
)

// =================================
//              SETTING
// =================================
var GWID = "b827ebfffe0c42f7"
// IOTA Setting
var node = "http://localhost:14266"
const depth = 3;
const minimumWeightMagnitude = 1;
const address = trinary.Trytes("ZLGVEQ9JUZZWCZXLWVNTHBDX9G9KZTJP9VEERIIFHY9SIQKYBVAHIMLHXPQVE9IXFDDXNHQINXJDRPFDXNYVAPLZAS")
const seed = trinary.Trytes("JBN9ZRCOH9YRUGSWIQNZWAIFEZUBDUGTFPVRKXWPAUCEQQFS9NHPQLXCKZKRHVCCUZNF9CZZWKXRZVCWQ")

// KEY LOCATION
var NS_PUBLIC_KEY_PATH = "key/pubNS1.key"  // FOR PAYLOAD ENC
var GW_PRIVATE_KEY_PATH = "key/priGWA.key" // FOR SIGN

var (
        BK_RST = "\033[0m"
        BK_RD = "\033[41;4m"
        BK_GN = "\033[42;4m"
        BK_YL = "\033[43;4m"
        BK_PL = "\033[44;1m"
        BK_BL = "\033[45;1m"
        BK_CY = "\033[46;4m"
        TX_WH = "\033[37;1m"
        TX_RST = "\033[0m"
)

// =================================
//		IOTA
// =================================

func getTagTx() trinary.Trytes{
        t := time.Now()
        str1 := t.Format("200601021504")
        tr, err := converter.ASCIIToTrytes(str1)
        must(err)
        return tr
}

func getTagForSearch() []trinary.Trytes{
        var ts []trinary.Trytes
        t := time.Now()
        str1, _ := converter.ASCIIToTrytes(t.Format("200601021504"))
        str2, _ := converter.ASCIIToTrytes(t.Add(time.Duration(-1) * time.Minute).Format("200601021504"))
        ts = append(ts, trinary.MustPad("N" +str1, 27),  trinary.MustPad("N"+str2, 27))
        return ts
}

func sendtx(b4 string, iota *api.API){
	log.Println(TX_WH + BK_PL + " UPLINK " + BK_RST + TX_RST + "\t", b4)
	message, err := converter.ASCIIToTrytes(b4)
	must(err)

	start := time.Now()

        transfers := bundle.Transfers{
                {
                        Address: address,
                        Value: 0,
                        Message: message,
                        Tag: getTagTx(),
                },
        }
	trytes, err := iota.PrepareTransfers(seed, transfers, api.PrepareTransfersOptions{})
	must(err)
	myBundle, err := iota.SendTrytes(trytes, depth, minimumWeightMagnitude)
	must(err)

	duration := time.Since(start)

	log.Println(TX_WH + BK_PL + " UPLINK " + BK_RST + TX_RST + "\t", time.Now(), bundle.TailTransactionHash(myBundle), getTagTx(), duration)
}

func fetchTx(iota *api.API) transaction.Transactions{
        tags := getTagForSearch()
        txs, _ := iota.FindTransactionObjects(api.FindTransactionsQuery {
                        Tags: tags,
        })
        sort.SliceStable(txs, func(i, j int) bool {
                return txs[i].AttachmentTimestamp > txs[j].AttachmentTimestamp
        })
        return txs
}

func waitConfirmed(h string, iota *api.API){
        var hs []string
        hs = append(hs, h)
        for {
                b, err := iota.GetInclusionStates(hs)
                must(err)
                if err == nil && b[0] == true{
                        return
                }
        }

}

// =================================
//              CRYPTO (RSA)
// =================================
func rsa_sign(msg_s string, key *rsa.PrivateKey) string {
        msg := []byte(msg_s)
        msgHash := sha256.New()
        _, err := msgHash.Write(msg)
        must(err)
        msgHashSum := msgHash.Sum(nil)
        signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, msgHashSum, nil)
        must(err)
        return b64.StdEncoding.EncodeToString(signature)
}

func rsa_verify(msg_s string, signature_b64 string, key *rsa.PublicKey) bool {
        msg := []byte(msg_s)
        msgHash := sha256.New()
        _, err := msgHash.Write(msg)
        must(err)
        msgHashSum := msgHash.Sum(nil)
        signature, err := b64.StdEncoding.DecodeString(signature_b64)
        must(err)
        err = rsa.VerifyPSS(key, crypto.SHA256, msgHashSum, signature, nil)
        if err != nil {
                return false
        }
        return true
}

func rsa_encrypt(msg  []byte, key *rsa.PublicKey) string {
        // params
        rnd := rand.Reader
        hash := sha256.New()

        // encrypt with OAEP
        ciperText, err := rsa.EncryptOAEP(hash, rnd, key, msg, nil)
        must(err)

        return b64.StdEncoding.EncodeToString(ciperText)
}

func rsa_decrypt(payload string, key *rsa.PrivateKey) []byte {
        // decode base64 encoded signature
        msg, err := b64.StdEncoding.DecodeString(payload)
        must(err)

        // params
        rnd := rand.Reader
        hash := sha256.New()

        // decrypt with OAEP
        plainText, err := rsa.DecryptOAEP(hash, rnd, key, msg, nil)
        must(err)

        return plainText
}

// Read Private / Public Key
func read_PRIVATE_PEM_KEY(path string) *rsa.PrivateKey{
        log.Println(TX_WH + BK_GN + "  INFO  " + BK_RST + TX_RST + "\t" ,"Reading key from file:", path)
        content, err := ioutil.ReadFile(path)
        must(err)
        text := string(content)
        block, _ := pem.Decode([]byte(text))
        key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
        must(err)
        return key
}

func read_PUBLIC_PEM_KEY(path string) *rsa.PublicKey{
        log.Println(TX_WH + BK_GN + "  INFO  " + BK_RST + TX_RST + "\t" , "Reading key from file:", path)
        content, err := ioutil.ReadFile(path)
        must(err)
        text := string(content)
        block, _ := pem.Decode([]byte(text))
        key, err := x509.ParsePKIXPublicKey(block.Bytes)
        must(err)
        var pubKey *rsa.PublicKey
        pubKey, _ = key.(*rsa.PublicKey)
        return pubKey
}

// =================================
//              CRYPTO (AES)
// =================================

func aes_RandomKey() []byte{
        token := make([]byte, 16)
        mrand.Read(token)
        return token
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
        padding := blockSize - len(ciphertext)%blockSize
        padtext := bytes.Repeat([]byte{byte(padding)}, padding)
        return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
        length := len(origData)
        unpadding := int(origData[length-1])
        return origData[:(length - unpadding)]
}

func AesEncrypt(plaintext []byte, key []byte, iv []byte) string {
        block, err := aes.NewCipher(key)
        must(err)
        blockSize := block.BlockSize()
        plaintext = PKCS7Padding(plaintext, blockSize)
        blockMode := cipher.NewCBCEncrypter(block, iv)
        crypted := make([]byte, len(plaintext))
        blockMode.CryptBlocks(crypted, plaintext)
        b := b64.StdEncoding.EncodeToString(crypted)
        return b
}

func AesDecrypt(ciphertext_64 string, key []byte, iv []byte) []byte {
        ciphertext, err := b64.StdEncoding.DecodeString(ciphertext_64)
        must(err)
        block, err := aes.NewCipher(key)
        must(err)
        blockSize := block.BlockSize()
        blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
        origData := make([]byte, len(ciphertext))
        blockMode.CryptBlocks(origData, ciphertext)
        origData = PKCS7UnPadding(origData)
        return origData
}

// =================================
//              UTILITY
// =================================

type Payload struct {
        GWID string
        AES_KEY string
        PAYLOAD string
        SIGN string
}

func string_to_payload(s string) Payload {
        p := Payload{}
        err := json.Unmarshal([]byte(s), &p)
        must(err)
        return p
}

func payload_to_string(p Payload) string {
        b, err := json.Marshal(p)
        must(err)
        return string(b)
}

func must(err error) {
        if err != nil {
                log.Println(TX_WH + BK_RD + "  ERROR " + BK_RST + TX_RST + "\t" ,err)
        }
}

func getGWID(b []byte) string {
        return hex.EncodeToString(b[4:12])
}

func Find(slice []*net.UDPAddr, val *net.UDPAddr) (int, bool) {
    for i, item := range slice {
        if item.String() == val.String() {
            return i, true
        }
    }
    return -1, false
}

// =================================
//	MIDDLEWARE (GW > MW)
// =================================

func response(b []byte, iota *api.API, ns_PUBLICKEY *rsa.PublicKey, gw_PRIVATEKEY *rsa.PrivateKey){
        log.Printf(TX_WH + BK_PL + " UPLINK " + BK_RST + TX_RST + "\t [GW>MW>Legder] %s\n", b)
	var p Payload
	p.GWID = getGWID(b)
	CIPHER_KEY := aes_RandomKey()
	p.AES_KEY = rsa_encrypt(CIPHER_KEY, ns_PUBLICKEY)
	p.PAYLOAD = AesEncrypt(b, CIPHER_KEY, CIPHER_KEY)
	p.SIGN = rsa_sign(p.GWID + p.AES_KEY + p.PAYLOAD, gw_PRIVATEKEY)
	p_s := payload_to_string(p)
	sendtx(p_s, iota)
}

var global_gw_addr []*net.UDPAddr
func GW2MW(iota *api.API, gwconn *net.UDPConn, ns_PUBLICKEY *rsa.PublicKey, gw_PRIVATEKEY *rsa.PrivateKey){
        for {
                b := make([]byte, 1024)
                n, addr, err := gwconn.ReadFromUDP(b)
                must(err)
		if _, found := Find(global_gw_addr, addr); !found{
			log.Println(TX_WH + BK_GN + "  INFO  " + BK_RST + TX_RST + "\t" ,"New GW<>MW Connection")
                        global_gw_addr = append(global_gw_addr, addr)
                }
		go response(b[0:n], iota, ns_PUBLICKEY, gw_PRIVATEKEY)
        }
}

// =================================
//      MIDDLEWARE (GW > MW)
// =================================

func forwardtoNS(t transaction.Transaction, gwconn *net.UDPConn, ns_PUBLICKEY *rsa.PublicKey, gw_PRIVATEKEY *rsa.PrivateKey){
	var ts []transaction.Transaction
        ts = append(ts ,t)
        b_enc, err := transaction.ExtractJSON(ts)
        must(err)
        p2 := string_to_payload(b_enc)
	if GWID != p2.GWID {
		return
	}
	ok := rsa_verify(p2.GWID + p2.AES_KEY + p2.PAYLOAD, p2.SIGN, ns_PUBLICKEY)
	if !ok {
                log.Println(TX_WH + BK_BL + "DOWNLINK" + BK_RST + TX_RST , "Got tx: ", t.Hash, " But verify fail")
                return
	}else{
		aeskey := rsa_decrypt(p2.AES_KEY, gw_PRIVATEKEY)
		dec_data := AesDecrypt(p2.PAYLOAD, aeskey, aeskey)
		log.Println(TX_WH + BK_BL + "DOWNLINK" + BK_RST + TX_RST ,"Got tx: ", t.Hash," From: NS ",  time.Unix(t.AttachmentTimestamp / 1000, t.AttachmentTimestamp % 1000 *1000000))
		if global_gw_addr != nil {
			log.Println(global_gw_addr)
			for _, a := range global_gw_addr {
				go gwconn.WriteToUDP(dec_data, a)
			}
		}else{
			log.Printf(TX_WH + BK_BL + "DOWNLINK" + BK_RST + TX_RST +" No gateway connection\n")
		}
	}
}

func MW2GW(iota *api.API, gwconn *net.UDPConn, ns_PUBLICKEY *rsa.PublicKey, gw_PRIVATEKEY *rsa.PrivateKey){
	var cur_ts int64
	cur_ts = 0
	txs := fetchTx(iota)
	if len(txs) > 0 {
		cur_ts = txs[len(txs) - 1].AttachmentTimestamp
	}
	for {
		txs := fetchTx(iota)
		if len(txs) > 0 {
			for _, t := range txs {
				if t.AttachmentTimestamp > cur_ts {
					log.Println(TX_WH + BK_BL + "DOWNLINK" + BK_RST + TX_RST ,"Wait for comfirm", t.Hash, time.Unix(t.AttachmentTimestamp / 1000, t.AttachmentTimestamp % 1000 *1000000))
					waitConfirmed(t.Hash, iota)
					cur_ts = t.AttachmentTimestamp
					go forwardtoNS(t, gwconn, ns_PUBLICKEY, gw_PRIVATEKEY)
				}
			}
		}
	}
}

// =================================
//      	Main
// =================================

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
        var node_f string
        var gw_f string
        var nkey_f string
        var gkey_f string

        flag.StringVar(&node_f, "node", "http://localhost:14265", "URI of IOTA node")
	flag.StringVar(&gw_f, "gw", "127.0.0.1:1700", "HOST:PORT of gateway pkt forwader")
        flag.StringVar(&nkey_f, "nkey", "key/pubNS1.key", "Path of network server public key")
        flag.StringVar(&gkey_f, "gkey", "key/priGWA.key", "Path of gateway private key")
	flag.StringVar(&GWID, "gwid", "b827ebfffe0c42f7", "Gatewat ID")
        flag.Parse()

        node = node_f
        gw_addr := gw_f

	NS_PUBLIC_KEY_PATH = nkey_f  // FOR PAYLOAD ENC
	GW_PRIVATE_KEY_PATH = gkey_f // FOR SIGN
        ns_PUBLICKEY := read_PUBLIC_PEM_KEY(NS_PUBLIC_KEY_PATH)
        gw_PRIVATEKEY := read_PRIVATE_PEM_KEY(GW_PRIVATE_KEY_PATH)

	gwaddr, err := net.ResolveUDPAddr("udp", gw_addr)
	must(err)
	gwconn, err := net.ListenUDP("udp", gwaddr)
	defer gwconn.Close()

	iota, err := api.ComposeAPI(api.HTTPClientSettings{URI: node})
	must(err)

	// goroutine
	finished := make(chan bool)
	go GW2MW(iota, gwconn, ns_PUBLICKEY, gw_PRIVATEKEY)
	go MW2GW(iota, gwconn, ns_PUBLICKEY, gw_PRIVATEKEY)
	<- finished
}
