package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"time"
)

type Ns struct {
	Nameserver, Target, IP string
}

var CurrentIP string
var NSes = make(map[string]Ns)

func init() {
	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "Must run with user root\n")
		os.Exit(4)
	}
	SetNSes()
	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dial := net.Dialer{
				Timeout: time.Millisecond * time.Duration(1500),
			}
			return dial.DialContext(ctx, network, NSes[`resolver1.opendns.com`].IP+`:53`) // opendns
		},
	}
	this, err := resolver.LookupHost(context.Background(), NSes[`resolver1.opendns.com`].Target)
	if err != nil {
		panic(err)
	}
	CurrentIP = this[0]
	ValidateIP(CurrentIP)
	log.Println(`Matching results with`, CurrentIP)
}

func ValidateIP(ip string) {
	regex, err := regexp.Compile(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`)
	if err != nil {
		panic(err)
	}
	if ok := regex.Match([]byte(ip)); !ok {
		log.Fatalf("%v is not a valid ip\n", ip)
	}
}

func SetNSes() {
	nses := []Ns{
		{Nameserver: `resolver1.opendns.com`, Target: `myip.opendns.com`},
		{Nameserver: `ns1-1.akamaitech.net`, Target: `whoami.akamai.net`},
	}

	for _, target := range nses {
		t, err := net.LookupHost(target.Nameserver)
		if err != nil {
			log.Fatalf("Can't resolve %v\n", target.Nameserver)
		}
		target.IP = t[0]
		NSes[target.Nameserver] = target
		log.Printf("Resolved NS %v to %v. Target is %v\n", target.Nameserver, target.IP, target.Target)
	}
}

func ChangeFWPolicy() {
	chains := []string{
		`INPUT`,
		`OUTPUT`,
	}
	for _, c := range chains {
		cmd := exec.Command(`/usr/sbin/iptables`, `-P`, c, `DROP`)
		err := cmd.Run()
		if err != nil {
			panic(err)
		}
		log.Printf("Changed %v default policy\n", c)
	}
}

func HttpCheck(ch chan string, httpServer, vip string) {
	var C int // to make sure if it's not just a problem with http request
	for {
		resp, err := http.Get(httpServer)
		if err != nil {
			log.Println(err)
			ch <- httpServer
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			ip, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Println(err)
				ch <- httpServer
			}
			if string(ip) != vip {
				log.Println(string(ip))
				ch <- httpServer
			}
			resp.Body.Close()
			C = 0
		} else if resp.StatusCode == 403 {
			ch <- httpServer
		} else {
			if C == 3 {
				resp.Body.Close()
				log.Printf("request response is not valid for 3 times in a row, http server = %v, latest response code = %d\n",
					httpServer, resp.StatusCode)
				log.Println("Going to sleep for 60s...")
				time.Sleep(time.Second * 60)
				C = 0
				log.Printf("Start using server %v again for HTTP checks\n.", httpServer)
			} else {
				C++
				resp.Body.Close()
				continue
			}
		}
	}
}

func DnsCheck(ch chan string, dnsServer, where, vip string) {
	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dial := net.Dialer{
				Timeout: time.Millisecond * time.Duration(700),
			}
			return dial.DialContext(ctx, network, dnsServer)
		},
	}
	for {
		addr, err := resolver.LookupHost(context.Background(), where)
		if err != nil {
			log.Println(err)
			ch <- dnsServer
		}
		if addr[0] != vip {
			ch <- dnsServer
		}
		time.Sleep(time.Duration(100) * time.Millisecond)
	}
}
