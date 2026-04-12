package model

import "time"

type IPResult struct {
	IP  string
	PTR []string
}

type HostIPs struct {
	Host string
	IPs  []IPResult
}

type MXHost struct {
	Host       string
	Preference uint16
	IPs        []IPResult
}

type SOAInfo struct {
	Serial  uint32
	Mbox    string
	NS      string
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

type RDAPEvent struct {
	Action string
	Date   string
}

type RDAPInfo struct {
	Domain     string
	Handle     string
	Events     []RDAPEvent
	Expired    bool
	Warn30Days bool
}

type Report struct {
	InputDomain string
	Domain      string
	IsSubdomain bool

	SubdomainIPs []IPResult
	ARecords     []string
	SOA          *SOAInfo
	Nameservers  []HostIPs
	MXRecords    []MXHost
	TXTRecords   []string
	SPFRecords   []string
	DMARCRecords []string
	CAARecords   []string
	NoCAA        bool

	RDAP      *RDAPInfo
	RDAPError bool

	GeneratedAt time.Time
}
