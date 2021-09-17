package nslookup

import (
	"encoding/binary"
	"errors"
	"golang.org/x/net/context"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ErrNotFound = errors.New("nslookup: domain record not found")
var ErrMaxDepth = errors.New("nslookip: depth is up to max")

func LookupA(domain string) (aResourceList []string, err error) {
	answerList, err := lookupResourceListL1(domain, dnsmessage.TypeA)
	if err != nil {
		return nil, err
	}
	for _, answer := range answerList {
		aResource, ok := answer.Body.(*dnsmessage.AResource)
		if !ok {
			continue
		}
		aResourceList = append(aResourceList, net.IPv4(aResource.A[0], aResource.A[1], aResource.A[2], aResource.A[3]).String())
	}
	if len(aResourceList) == 0 {
		return nil, ErrNotFound
	}
	return aResourceList, err
}

func LookupSOA(domain string) (soaResourceList []string, err error) {
	answerList, err := lookupResourceListL1(domain, dnsmessage.TypeSOA)
	if err != nil {
		return nil, err
	}
	for _, answer := range answerList {
		soaResource, ok := answer.Body.(*dnsmessage.SOAResource)
		if !ok {
			continue
		}
		soaResourceList = append(soaResourceList, strings.TrimSuffix(soaResource.NS.String(), "."))
	}
	if len(soaResourceList) == 0 {
		return nil, ErrNotFound
	}
	return soaResourceList, nil
}

func LookupNS(domain string) (nsResourceList []string, err error) {
	answerList, err := lookupResourceListL1(domain, dnsmessage.TypeNS)
	if err != nil {
		return nil, err
	}
	for _, answer := range answerList {
		nsResource, ok := answer.Body.(*dnsmessage.NSResource)
		if !ok {
			continue
		}
		nsResourceList = append(nsResourceList, strings.TrimSuffix(nsResource.NS.String(), "."))
	}
	if len(nsResourceList) == 0 {
		return nil, ErrNotFound
	}
	return nsResourceList, nil
}

func LookupTXT(domain string) (txtResourceList []string, err error) {
	answerList, err := lookupResourceListL1(domain, dnsmessage.TypeTXT)
	if err != nil {
		return nil, err
	}
	for _, answer := range answerList {
		txtResource, ok := answer.Body.(*dnsmessage.TXTResource)
		if !ok {
			continue
		}
		txtResourceList = append(txtResourceList, txtResource.TXT...)
	}
	if len(txtResourceList) == 0 {
		return nil, ErrNotFound
	}
	return txtResourceList, nil
}

func LookupCNAME(domain string) (cname string, err error) {
	answerList, err := lookupResourceListL1(domain, dnsmessage.TypeTXT)
	if err != nil {
		return "", err
	}
	for _, answer := range answerList {
		cnameResource, ok := answer.Body.(*dnsmessage.CNAMEResource)
		if !ok {
			continue
		}
		cname = cnameResource.CNAME.String()
		if cname != `` {
			break
		}
	}
	if cname == "" {
		return "", ErrNotFound
	}
	return cname, nil
}

func LookupMX(domain string) (mxResourceList []net.MX, err error) {
	answerList, err := lookupResourceListL1(domain, dnsmessage.TypeMX)
	if err != nil {
		return nil, err
	}
	for _, answer := range answerList {
		mxResource, ok := answer.Body.(*dnsmessage.MXResource)
		if !ok {
			continue
		}
		mxResourceList = append(mxResourceList, net.MX{
			Host: mxResource.MX.String(),
			Pref: mxResource.Pref,
		})
	}
	if len(mxResourceList) == 0 {
		return nil, ErrNotFound
	}
	sort.Slice(mxResourceList, func(i, j int) bool {
		a, b := mxResourceList[i], mxResourceList[j]
		if a.Pref != b.Pref {
			return a.Pref > b.Pref
		}
		return a.Host < b.Host
	})
	return mxResourceList, nil
}

func lookupResourceListL1(domain string, typeC dnsmessage.Type) (resourceList []dnsmessage.Resource, err error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	name, err := dnsmessage.NewName(domain)
	if err != nil {
		return nil, err
	}
	msg := &dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 uint16(atomic.AddUint32(&gLookupId, 1)),
			Response:           false,
			OpCode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			RCode:              0,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  name,
				Type:  typeC,
				Class: dnsmessage.ClassINET,
			},
		},
		Answers:     nil,
		Authorities: nil,
		Additionals: nil,
	}
	send, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	serverList := gRootServers
	for depth := 0; ; depth++ {
		if depth > 10 {
			return nil, ErrMaxDepth
		}
		var conn net.Conn
		conn, err = gDialRemote(serverList)
		if err != nil {
			return nil, err
		}
		var receive []byte
		receive, err = exchangePacket(conn, send)
		_ = conn.Close()
		if err != nil {
			return nil, err
		}
		var receiveMsg dnsmessage.Message
		err = receiveMsg.Unpack(receive)
		if err != nil {
			return nil, err
		}
		if len(receiveMsg.Answers) > 0 {
			return receiveMsg.Answers, nil
		}
		var nsList []string
		for _, one := range receiveMsg.Authorities {
			nsResource, ok := one.Body.(*dnsmessage.NSResource)
			if ok {
				nsList = append(nsList, strings.TrimSuffix(nsResource.NS.String(), ".")+":53")
			}
		}
		if nsList == nil {
			return nil, ErrNotFound
		}
		serverList = nsList
	}
}

var gDialRemote = func(targetAddrList []string) (conn net.Conn, err error) {
	if len(targetAddrList) == 0 {
		return nil, errors.New("LookupContext.DialRemote targetAddrList is nil")
	}
	wg := sync.WaitGroup{}
	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second*10)
	var errList []error
	var locker sync.Mutex

	for _, addr := range targetAddrList {
		addr := addr
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn0, err0 := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			locker.Lock()
			defer locker.Unlock()

			if err0 != nil {
				errList = append(errList, err0)
				return
			}
			if conn != nil {
				conn0.Close() // 同时有多个线程连接成功, 后面成功的就关闭丢弃
				return
			}
			conn = conn0
			cancelFn()
		}()
	}
	wg.Wait()

	if conn == nil {
		return nil, errList[0]
	}
	return conn, nil
}

func exchangePacket(conn net.Conn, send []byte) (receive []byte, err error) {
	var temp = make([]byte, 2+math.MaxUint16)
	binary.BigEndian.PutUint16(temp, uint16(len(send)))
	copy(temp[2:], send)

	_, err = conn.Write(temp[:2+len(send)])
	if err != nil {
		return nil, err
	}
	_, err = io.ReadFull(conn, temp[:2])
	if err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(temp)
	_, err = io.ReadFull(conn, temp[2:2+n])
	if err != nil {
		return nil, err
	}
	return temp[2 : 2+n], nil
}

var gRootServers = []string{
	"198.41.0.4:53",
	"192.228.79.201:53",
	"192.33.4.12:53",
	"128.8.10.90:53",
	"192.203.230.10:53",
	"192.5.5.241:53",
	"192.112.36.4:53",
	"128.63.2.53:53",
	"192.36.148.17:53",
	"192.58.128.30:53",
	"193.0.14.129:53",
	"199.7.83.42:53",
	"202.12.27.33:53",
}

//a.root-servers.net 	198.41.0.4	NS.INTERNIC.NET	VeriSign, Inc.		6
//b.root-servers.net 	192.228.79.201	NS1.ISI.EDU	Information Sciences Institute	美国	1
//c.root-servers.net 	192.33.4.12	C.PSI.NET	PSINet公司	美国	6
//d.root-servers.net 	128.8.10.90	TERP.UMD.EDU	University of Maryland	美国	1
//e.root-servers.net 	192.203.230.10	NS.NASA.GOV	NASA Ames Research Center	美国	1
//f.root-servers.net 	192.5.5.241	NS.ISC.ORG	Internet Systems Consortium, Inc.	美国	49
//g.root-servers.net 	192.112.36.4	NS.NIC.DDN.MIL	国防部网络信息中心	美国	6
//h.root-servers.net 	128.63.2.53	AOS.ARL.ARMY.MIL	陆军研究所	美国	1
//i.root-servers.net 	192.36.148.17	NIC.NORDU.NET	Autonomica	挪威	36
//j.root-servers.net 	192.58.128.30		VeriSign, Inc.	美国	70
//k.root-servers.net 	193.0.14.129		RIPE NCC	欧洲	18
//l.root-servers.net 	199.7.83.42		ICANN		31
//m.root-servers.net 	202.12.27.33		WIDE Project	日本	6

var gLookupId uint32
