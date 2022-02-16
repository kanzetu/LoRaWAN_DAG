package main

import (
	. "github.com/iotaledger/iota.go/api"
	"github.com/iotaledger/iota.go/bundle"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/iotaledger/iota.go/converter"
	"fmt"
	"time"
//	"os"
//	"strconv"
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

func main() {
    delay := flag.Int("d", 250, "MAX concurrent")
    flag.Parse()
    // compose a new API instance, we provide no PoW function so this uses remote PoW
    api, err := ComposeAPI(HTTPClientSettings{URI: node})
    must(err)

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
    for {
    go func(){
    start := time.Now()
    prepTransferOpts := PrepareTransfersOptions{}
    trytes, err := api.PrepareTransfers(seed, transfers, prepTransferOpts)
    must(err)
    // Create a bundle from the `transfers` object
    // and send the transaction to the node
    myBundle, err := api.SendTrytes(trytes, depth, minimumWeightMagnitude)
    must(err)


    duration := time.Since(start)
    if len(myBundle) > 0{
        fmt.Println("Bundle hash: " + myBundle[0].Bundle + " ", duration)
    }
    }()
    time.Sleep(time.Duration(*delay) * time.Microsecond)
    }
}

func must(err error) {
    if err != nil {
        fmt.Println(err)
    }
}
