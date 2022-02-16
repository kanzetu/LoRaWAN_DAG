package main
import (
	"fmt"
	"net"
)

const ns_addr = "vmns1.local:1700"
var global_gw_addr []*net.UDPAddr

func main() {
	gwaddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:1700")
	must(err)
	gwconn, err := net.ListenUDP("udp", gwaddr)
	defer gwconn.Close()

	nsaddr, err := net.ResolveUDPAddr("udp", ns_addr)
	must(err)
	nsconn, err := net.DialUDP("udp", nil, nsaddr)
	must(err)
	finished := make(chan bool)
	go gw_listener(gwconn, nsconn)
	go ns_listener(gwconn,nsconn)

	<- finished
}
func gw_listener(gwconn *net.UDPConn, nsconn *net.UDPConn){
	for {
		b := make([]byte, 1024)
		n, addr, err := gwconn.ReadFromUDP(b)
		must(err)
		if _, found := Find(global_gw_addr, addr); !found{
			global_gw_addr = append(global_gw_addr, addr)
		}
		fmt.Printf("[GW>NS] %s\n", b)
		go nsconn.Write(b[0:n])
	}
	fmt.Printf("GW Done")
}

func ns_listener(gwconn *net.UDPConn,nsconn *net.UDPConn){
	for {
		p := make([]byte, 1024)
		n, _, err := nsconn.ReadFromUDP(p)
		must(err)
		fmt.Printf("[NS>GW] %s\n", p[0:n])
		if global_gw_addr != nil {
			fmt.Println(global_gw_addr)
			for _, a := range global_gw_addr {
				go gwconn.WriteToUDP(p[0:n], a)
			}
		}else{
			fmt.Printf("No gateway connection\n")
		}
	}
	fmt.Printf("NS Done")
}


func must(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func Find(slice []*net.UDPAddr, val *net.UDPAddr) (int, bool) {
    for i, item := range slice {
        if item.String() == val.String() {
            return i, true
        }
    }
    return -1, false
}
