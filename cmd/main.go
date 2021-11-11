package main

import (
	"log"
	"os"
)

func main() {
	var (
		ch = make(chan string)
	)
	for _, md := range NSes {
		go DnsCheck(ch, md.IP+`:53`, md.Target, CurrentIP)
	}
	go HttpCheck(ch, `https://api.ipify.org`, CurrentIP)
	go HttpCheck(ch, `https://ifconfig.me`, CurrentIP)
	select {
	case from := <-ch:
		log.Println(from)
		ChangeFWPolicy()
		os.Exit(1)
	}
}
