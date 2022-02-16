package stat

import (
	. "github.com/iotaledger/iota.go/api"
	"github.com/iotaledger/iota.go/bundle"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/iotaledger/iota.go/converter"
	"fmt"
	"time"
	"io/ioutil"
	"os"
	"strconv"
	"flag"
)

var node = "http://localhost:14265"

const seed = trinary.Trytes("JBN9ZRCOH9YRUGSWIQNZWAIFEZUBDUGTFPVRKXWPAUCEQQFS9NHPQLXCKZKRHVCCUZNF9CZZWKXRZVCWQ")
const address = trinary.Trytes("XBN9ZRCOH9YRUGSWIQNZWAIFEZUBDUGTFPVRKXWPAUCEQQFS9NHPQLXCKZKRHVCCUZNF9CZZWKXRZVCWQMZOCAHYPD")

// Define a message to send.
// This message must include only ASCII characters.
var data = "{'message' : 'Hello world'}"

const minimumWeightMagnitude = 1
const depth = 3
const maxtx = 1000

func main() {
    // compose a new API instance, we provide no PoW function so this uses remote PoW
    api, err := ComposeAPI(HTTPClientSettings{URI: node})
    must(err)

    d := flag.Int("d", 250, "Delay for each transaction")
    var f string
    flag.StringVar(&f, "f", "log", "Output filename")
    var n string
    flag.StringVar(&n, "n", "http://localhost:14265", "Node URI")

    flag.Parse()

    fname := f
    delay := *d
    node = n

    // Convert the message to trytes
    message, err := converter.ASCIIToTrytes(data)
    must(err)

    // Define a zero-value transaction object
    // that sends the message to the address
    transfers := bundle.Transfers{
        {
            Address: address,
            Value: 0,
            Message: message,
        },
    }
    // Use the default options
    ioutil.WriteFile(fname, []byte(""), 0644)
    file, err := os.OpenFile(fname, os.O_APPEND|os.O_WRONLY, 0644)
    must(err)
    defer file.Close()
    i := 0
    for {
	if i >= maxtx{
		os.Exit(0)
	}
    	go func(){
    		start := time.Now()
    		prepTransferOpts := PrepareTransfersOptions{}
    		trytes, err := api.PrepareTransfers(seed, transfers, prepTransferOpts)
    		must(err)
    		myBundle, err := api.SendTrytes(trytes, depth, minimumWeightMagnitude)
    		must(err)


    		duration := time.Since(start)
		if len(myBundle) > 0 {
    			fmt.Println("Bundle hash: " + myBundle[0].Bundle + " ", duration)
			file.WriteString(strconv.FormatInt(duration.Microseconds(), 10) + "\n")
                	i = i + 1
		}
    	}()
    	time.Sleep(time.Duration(delay) * time.Millisecond)
    }
}

func must(err error) {
    if err != nil {
        fmt.Println(err)
    }
}
