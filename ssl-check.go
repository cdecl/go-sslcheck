package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"time"
)

type ChainInfo struct {
	Host       string `json:"domain"`
	IP         string `json:"ip"`
	Name       string `json:"publish"`
	ExpireDate string `json:"expr-date"`
	Expire     int    `json:"expr"`
	Error      string `json:"error"`
}

func fmtDurDay(d time.Duration) int {
	d = d.Round(time.Hour)
	return int(d.Hours() / 24)
}

func createChainInfo(h string) ChainInfo {
	cinfo := ChainInfo{}
	cinfo.Host = h
	r, err := net.LookupIP(cinfo.Host)

	if err == nil {
		cinfo.IP = fmt.Sprintf("%v", r[0])
	}

	return cinfo
}

func updateInfo(cinfo *ChainInfo, cert *x509.Certificate) {
	cinfo.ExpireDate = fmt.Sprintf("%s", cert.NotAfter)[0:10]
	cinfo.Expire = fmtDurDay(cert.NotAfter.Sub(time.Now()))
	cinfo.Name = cert.Subject.CommonName
	cinfo.Error = "OK"
}

func checkSSLImpl(h string) ChainInfo {
	cinfo := createChainInfo(h)

	IP := fmt.Sprintf("[%s]:%d", cinfo.IP, 443)
	dialer := net.Dialer{Timeout: time.Second * 5}

	conn, err := tls.DialWithDialer(&dialer, "tcp", IP, &tls.Config{ServerName: h})
	if err != nil {
		cinfo.Error = fmt.Sprintf("%v", err)
		return cinfo
	}
	defer conn.Close()

	for _, chain := range conn.ConnectionState().VerifiedChains {
		for _, cert := range chain {
			if cert.IsCA {
				continue
			}
			updateInfo(&cinfo, cert)
		}
	}
	return cinfo
}

func checkSSL(h string, chChain chan ChainInfo) {
	cinfo := checkSSLImpl(h)
	chChain <- cinfo
}

func checkRun(domainlist []string) []ChainInfo {
	chChain := make(chan ChainInfo, 0)
	defer close(chChain)

	for _, host := range domainlist {
		go checkSSL(host, chChain)
	}

	cinfolist := []ChainInfo{}
	for i := 0; i < len(domainlist); i++ {
		cinfo := <-chChain
		cinfolist = append(cinfolist, cinfo)
	}

	return cinfolist
}

func readDomain(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)

	domainlist := []string{}
	for scanner.Scan() {
		host := scanner.Text()
		if len(host) == 0 || host[0] == '#' {
			continue
		}
		domainlist = append(domainlist, host)
	}
	return domainlist
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	domainlist := readDomain("server_list.txt")
	cinfolist := checkRun(domainlist)

	sort.Slice(cinfolist, func(i, j int) bool {
		return cinfolist[i].ExpireDate < cinfolist[j].ExpireDate
	})

	fmtStr := "| %35s | %-15s | %30s | %10s | %4d | %s | \n"
	for _, c := range cinfolist {
		// js, _ := json.Marshal(c)
		// fmt.Println(string(js))
		fmt.Printf(fmtStr, c.Host, c.IP, c.Name, c.ExpireDate, c.Expire, c.Error)
	}

	fmt.Println("check count :", len(cinfolist))
}
