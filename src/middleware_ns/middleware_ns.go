package main
import (
        "log"
        "time"
	"sort"
	"net"
	"flag"
        "io/ioutil"
	"strings"
	"bytes"

        "crypto"
        "crypto/rsa"
        "crypto/x509"
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "crypto/sha256"

	mrand "math/rand"

	b64 "encoding/base64"
        "encoding/pem"
        "encoding/json"

	"github.com/iotaledger/iota.go/transaction"
        "github.com/iotaledger/iota.go/api"
        "github.com/iotaledger/iota.go/converter"
        "github.com/iotaledger/iota.go/trinary"
	"github.com/iotaledger/iota.go/bundle"
)

// =================================
//              SETTING
// =================================

// IOTA setting
var node = "http://localhost:14265"
var ns_addr = "localhost:1700"
const depth = 3;
const minimumWeightMagnitude = 1;
const address = trinary.Trytes("ZLGVEQ9JUZZWCZXLWVNTHBDX9G9KZTJP9VEERIIFHY9SIQKYBVAHIMLHXPQVE9IXFDDXNHQINXJDRPFDXNYVAPLZAS")
const seed = trinary.Trytes("JBN9ZRCOH9YRUGSWIQNZWAIFEZUBDUGTFPVRKXWPAUCEQQFS9NHPQLXCKZKRHVCCUZNF9CZZWKXRZVCWQ")

// KEY LOCATION
var NS_PRIVATE_KEY_PATH = "priNS1.key"  // FOR PAYLOAD DEC


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
//              Logger
// =================================

func Logger(){
		i := 0
		for _, g := range gateway_list{
			log.Println(TX_WH + BK_GN + "  INFO  " + BK_RST + TX_RST + "\t", g.CONNECT)
			if g.CONNECT != (*net.UDPConn) (nil) {
				i++
			}
		}
		log.Printf(TX_WH + BK_GN + "  INFO  " + BK_RST + TX_RST + "\t" + " Current %d/%d Gateway connection", i, len(gateway_list))
}

// =================================
//              IOTA
// =================================

func getTagForSearch() []trinary.Trytes{
	var ts []trinary.Trytes
	t := time.Now()
	str1, _ := converter.ASCIIToTrytes(t.Format("200601021504"))
	str2, _ := converter.ASCIIToTrytes(t.Add(time.Duration(-1) * time.Minute).Format("200601021504"))
	ts = append(ts, trinary.MustPad(str1, 27),  trinary.MustPad(str2, 27))
	return ts
}

func getTagTx() trinary.Trytes{
        t := time.Now()
        str1 := t.Format("200601021504")
        tr, err :=  converter.ASCIIToTrytes(str1)
        must(err)
        return "N" + tr
}

func sendtx(b4 string, iota *api.API){
        log.Println(TX_WH + BK_BL + "DOWNLINK" + BK_RST + TX_RST + "\t", b4)
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

        log.Println(TX_WH + BK_BL + "DOWNLINK" + BK_RST + TX_RST + "\t", time.Now(), bundle.TailTransactionHash(myBundle), getTagTx(), duration)
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
	start := time.Now()
	for {
		b, err := iota.GetInclusionStates(hs)
		must(err)
		if contains(b){
			return
		}
		t := time.Now().Sub(start)
		if (t > 3 * time.Second){
			return
		}
	}

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
                log.Println(TX_WH + BK_RD + "  ERROR " + BK_RST + TX_RST + "\t" ,"MW", err)
        }
}

type Gateway struct {
	GWID string
	PUBLICKEY *rsa.PublicKey
	CONNECT *net.UDPConn
	LISTENING bool
}

var gateway_list []Gateway

func fetchGateway(path string){
	files, err := ioutil.ReadDir(path)
	must(err)
	for _, f := range files {
		if strings.Contains(f.Name(), ".key"){
			var g Gateway
			pub_path := path + "/" + f.Name()
			g.GWID = strings.Split(f.Name(), ".key")[0]
			g.PUBLICKEY = read_PUBLIC_PEM_KEY(pub_path)
			g.LISTENING = false
			gateway_list = append(gateway_list, g)
		}
	}
}

func findGatewayById(id string) (Gateway, int){
	for i, g := range gateway_list {
		if g.GWID == id {
			return g, i
		}
	}
	var g Gateway
	return g, -1
}

func contains(slice []bool) bool {
    for _, item := range slice {
        if item  {
            return true
        }
    }
    return false
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
        log.Println(TX_WH + BK_GN + "  INFO  " + BK_RST + TX_RST + "\t" ,"Reading key from file:", path)
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
//        MIDDLEWARE (MW>NS)
// =================================

func forwardtoNS(t transaction.Transaction, ns_PRIVATEKEY *rsa.PrivateKey){
	var ts []transaction.Transaction
	ts = append(ts ,t)
	b_enc, err := transaction.ExtractJSON(ts)
	must(err)
	p2 := string_to_payload(b_enc)
	gateway, i := findGatewayById(p2.GWID)
	if i == -1 {
		log.Println(TX_WH + BK_PL + " UPLINK " + BK_RST + TX_RST + "\t" , "Got tx: ", t.Hash, " But gateway[", p2.GWID, "] Not Found")
		return
	}
	gw_PUBLICKEY := gateway.PUBLICKEY
	ok := rsa_verify(p2.GWID + p2.AES_KEY + p2.PAYLOAD, p2.SIGN, gw_PUBLICKEY)
	if !ok {
		log.Println(TX_WH + BK_RD + "  ERROR " + BK_RST + TX_RST + "\t" ,"Got tx: ", t.Hash, " But verify fail")
		return
	}else{
		aeskey := rsa_decrypt(p2.AES_KEY, ns_PRIVATEKEY)
		dec_data := AesDecrypt(p2.PAYLOAD, aeskey, aeskey)
		gw_id := p2.GWID
		log.Println(TX_WH + BK_PL + " UPLINK " + BK_RST + TX_RST + "\t" ,"Got tx: ", t.Hash," From: ", gw_id, " ",  time.Unix(t.AttachmentTimestamp / 1000, t.AttachmentTimestamp % 1000 *1000000))
		if gateway.CONNECT == nil {
			log.Println(TX_WH + BK_GN + "  INFO  " + BK_RST + TX_RST + "\t" ,"New Gateway found: ", gw_id)
        		nsaddr, err := net.ResolveUDPAddr("udp", ns_addr)
        		must(err)
        		nsconn, err := net.DialUDP("udp", nil, nsaddr)
        		must(err)
			gateway_list[i].CONNECT = nsconn
		}
		gateway_list[i].CONNECT.Write(dec_data)
	}
}

func MW2NS(iota *api.API, ns_PRIVATEKEY *rsa.PrivateKey){
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
                                        log.Println(TX_WH + BK_PL + " UPLINK " + BK_RST + TX_RST + "\t" ,"Wait for comfirm", t.Hash, time.Unix(t.AttachmentTimestamp / 1000, t.AttachmentTimestamp % 1000 *1000000))
                                        waitConfirmed(t.Hash, iota)
                                        cur_ts = t.AttachmentTimestamp
                                        go forwardtoNS(t, ns_PRIVATEKEY)
                                }
                        }
                }
        }
}

// =================================
//        MIDDLEWARE (NS>MW)
// =================================
func ListenNS(g Gateway, ns_PRIVATEKEY *rsa.PrivateKey, iota *api.API){
	for {
		var p Payload
		d := make([]byte, 1024)
		n, _, err := g.CONNECT.ReadFromUDP(d)
		must(err)
		log.Printf(TX_WH + BK_BL + "DOWNLINK" + BK_RST + TX_RST + "\t" +" [NS>GW] %s to %s\n", d[0:n], g.GWID)
		p.GWID = g.GWID
		CIPHER_KEY := aes_RandomKey()
		p.AES_KEY = rsa_encrypt(CIPHER_KEY, g.PUBLICKEY)
		p.PAYLOAD = AesEncrypt(d[0:n], CIPHER_KEY, CIPHER_KEY)
		p.SIGN = rsa_sign(p.GWID + p.AES_KEY + p.PAYLOAD, ns_PRIVATEKEY)
		p_s := payload_to_string(p)
		sendtx(p_s, iota)
	}
}

func NS2MW(ns_PRIVATEKEY *rsa.PrivateKey, iota *api.API){
	for {
		for i, g := range gateway_list {
			if (! g.LISTENING) &&  (g.CONNECT != nil) {
				gateway_list[i].LISTENING = true
				log.Println(TX_WH + BK_GN + "  INFO  " + BK_RST + TX_RST + "\t" ,"New NS connection for GW: ", g.GWID)
				go ListenNS(gateway_list[i], ns_PRIVATEKEY, iota)
			}
		}
	}
}


// =================================
//        MAIN
// =================================

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	var node_f string
	var ns_f string
	var nkey_f string
	var gkey_f string

	// Load cli flag
	flag.StringVar(&node_f, "node", "http://localhost:14265", "URI of IOTA node")
	flag.StringVar(&ns_f, "ns", "localhost:1700", "HOST:PORT of network server")
	flag.StringVar(&nkey_f, "nkey", "priNS1.key", "Path of network server private key")
	flag.StringVar(&gkey_f, "gkey", "key", "Path of gateway public key")
	flag.Parse()

	node = node_f
	ns_addr = ns_f
	NS_PRIVATE_KEY_PATH = nkey_f

	// Initiate IOTA
	iota, err := api.ComposeAPI(api.HTTPClientSettings{URI: node})
	must(err)

	// Fetch NS and GW information
        ns_PRIVATEKEY := read_PRIVATE_PEM_KEY(NS_PRIVATE_KEY_PATH)
	fetchGateway(gkey_f)

	// Start goroutine
	finished := make(chan bool)
	go MW2NS(iota, ns_PRIVATEKEY)
	go NS2MW(ns_PRIVATEKEY, iota)
	go Logger()
	<- finished
}
