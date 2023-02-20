package network

import (
	"log"

	"github.com/coreos/go-iptables/iptables"
)

type oakestraIpTable struct {
	iptable *iptables.IPTables
}

type IpTable interface {
	Append(string, string, ...string) error
	AppendUnique(string, string, ...string) error
	Delete(string, string, ...string) error
	DeleteChain(string, string) error
	AddChain(string, string) error
}

func NewOakestraIpTable() IpTable {
	iptable, ipterr := iptables.New()
	if ipterr != nil {
		log.Fatalln(ipterr)
	}
	oakestraiptable := &oakestraIpTable{
		iptable: iptable,
	}
	return oakestraiptable
}

func NewOakestraIP6Table() IpTable {
	ip6table, ipt6err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if ipt6err != nil {
		log.Fatalln(ipt6err)
	}
	oakestraiptable := &oakestraIpTable{
		iptable: ip6table,
	}
	return oakestraiptable
}

func (t *oakestraIpTable) Append(table string, chain string, params ...string) error {
	t.iptable.Append(table, chain, params...)
	return t.iptable.Append(table, chain, params...)
}

func (t *oakestraIpTable) AppendUnique(table string, chain string, params ...string) error {
	return t.iptable.AppendUnique(table, chain, params...)
}

func (t *oakestraIpTable) Delete(table string, chain string, params ...string) error {
	return t.iptable.Delete(table, chain, params...)
}

func (t *oakestraIpTable) DeleteChain(table string, chain string) error {
	return t.iptable.ClearAndDeleteChain(table, chain)
}

func (t *oakestraIpTable) AddChain(table string, chain string) error {
	return t.iptable.NewChain(table, chain)
}
