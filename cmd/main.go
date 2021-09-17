package main

import (
	"fmt"
	"github.com/orestonce/nslookup"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

var root = &cobra.Command{
	Use: "nslookup",
}

func main() {
	root.Execute()
}

func init() {
	var lookupType string
	root.Flags().StringVarP(&lookupType, "type", "t", "A", "查询类型[A, SOA, NS, TXT, CNAME, MX]")
	root.Run = func(cmd *cobra.Command, args []string) {
		if cmd.Flags().NArg() < 1 {
			fmt.Println("nslookup 需要输入要查询的域名")
			os.Exit(-1)
			return
		}
		for _, domain := range args {
			fmt.Println("查询", domain, "的", lookupType, "记录")
			lookupType = strings.ToUpper(lookupType)
			var fn func(domain string) (valueList []string, err error)

			switch lookupType {
			case "A":
				fn = nslookup.LookupA
			case "SOA":
				fn = nslookup.LookupSOA
			case "NS":
				fn = nslookup.LookupNS
			case "TXT":
				fn = nslookup.LookupTXT
			}
			if fn != nil {
				var valueList []string
				var err error
				valueList, err = fn(domain)
				if err != nil {
					fmt.Println("查询出错", err)
					continue
				}
				fmt.Println("查询到", len(valueList), "条", lookupType, "记录")
				for idx, value := range valueList {
					fmt.Println(idx+1, value)
				}
				continue
			}
			if lookupType == "CNAME" {
				cname, err := nslookup.LookupCNAME(domain)
				if err != nil {
					fmt.Println("查询出错", err)
					os.Exit(-1)
				}
				fmt.Println("查询到 CNAME 记录", cname)
				continue
			}
			if lookupType == "MX" {
				valueList, err := nslookup.LookupMX(domain)
				if err != nil {
					fmt.Println("查询出错", err)
					continue
				}
				fmt.Println("查询到", len(valueList), "条 MX 记录")
				for idx, value := range valueList {
					fmt.Println(idx+1, "优先级", value.Pref, "主机", value.Host)
				}
				continue
			}
			cmd.Help()
			return
		}
	}
}
