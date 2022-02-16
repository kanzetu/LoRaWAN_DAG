# LoRaWAN DAG

### Introduction
This project proposed a low-letancy secure data transmission channels within LoRaWAN infrastructure, by integrating DAG-chain.

The data channels between all gateways and Network server are vulnerable due to unsecure UDP channels. By implenmenting DAG-chain, discentralized ledger for all packets can provide self validation. Also, all packet is additional secured with RSA and AES to avoid sniffing.

###  Prerequisites
#### Software
- LoRaWAN DAG
	- golang
- LoRaWAN infrastructure
	- ChirpStack Gateway Bridge
	- Chirpstack Network Server
	- Chirpstack Application Server

- DAG
	- IOTA hornet

- Key pairs
	- Generating RSA-2048 key pair for Network server and each gateway
	- Network server should store its privacy key, and all gateways public key
	- Gateway should store its privacy key, and Network server public key

#### Hardware
- LoRaWAN gateway
	- Tested LoRaWAN Gateway models
		- RAK:  RAK7249, RAK7258
		- MultiTech Conduit
		- Milesight UG65, UG67

### Setup
```bash
git clone
cd
```
#### Hornet
- Start hornet coordinator
```bash
cd hornet/coordinator
export COO_SEED='PUEOTSEITFEVEWCWBTSIZM9NKRGJEIMXTULBACGFRQK9IMGICLBKW9TTEVSDQMGWKBXPVCBMMCXWMNPDX'
hornet -d . tool merkle
hornet --cooBootstrap
```

#### Build
- Middleware for Network server
```bash
cd middleware_ns
go build .
```
- Middleware for Gateway
	- As gateway leaks of resources to build the program, it is expected scp to the gateway after build.

```bash
cd middleware_gw
# For RAK and milesight gateway
env GOOS=linux GOARCH=mipsle go build .
# For multitech gateway
env GOOS=linux GOARCH=arm go build .
```
- udp_sniffer
```bash
cd udp_sniffer
go build .
```

- TPS tester
```bash
cd tester
go build main.go
go build stat.go
```

### Usage
- middleware_gw
```
./middleware_gw [options]
  -h
        help
  -gkey string
        Path of gateway private key (default "key/priGWA.key")
  -gw string
        HOST:PORT of gateway pkt forwader (default "127.0.0.1:1700")
  -gwid string
        Gatewat ID (default "b827ebfffe0c42f7")
  -nkey string
        Path of network server public key (default "key/pubNS1.key")
  -node string
        URI of IOTA node (default "http://localhost:14265")
```

- middleware_ns
```
./middleware_ns [options]
  -h
        help
  -gkey string
        Path of gateway public key (default "key")
  -nkey string
        Path of network server private key (default "priNS1.key")
  -node string
        URI of IOTA node (default "http://localhost:14265")
  -ns string
        HOST:PORT of network server (default "localhost:1700")
```

- udp-sniffer
```
./udp-sniffer
```

- tester main
```
./main
  -h
        help
  -d int
        MAX concurrent (default 250)
```