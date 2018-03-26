package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"

	"github.com/miekg/dns"
)

type record struct {
	name string
	ip   string
}

type rrDB struct {
	records []*masterFile
	ips     map[string][]*masterFile
	domains map[string][]*masterFile
}

func newRRDB() *rrDB {
	return &rrDB{
		ips:     map[string][]*masterFile{},
		domains: map[string][]*masterFile{},
	}
}

func (r *rrDB) Write() error {
	for _, rec := range r.records {
		if err := rec.write(); err != nil {
			return err
		}
	}
	return nil
}

func (r *rrDB) UpdateIP(domain string, ip string) {
	for _, mf := range r.domains[domain] {
		mf.updateIP(domain, ip)
	}
}

func (r *rrDB) Process(files []string) error {
	for _, x := range files {
		file, err := os.Open(x)
		if err != nil {
			return err
		}
		mf := r.newMasterFile(x)
		mf.process(dns.ParseZone(file, "", x))
	}
	return nil
}

func (r *rrDB) newMasterFile(name string) *masterFile {
	mf := newMasterFile(name)
	mf.parent = r
	r.records = append(r.records, mf)
	return mf
}

type masterFile struct {
	file    string
	parent  *rrDB
	records []*authority
	ips     map[string][]*authority
	domains map[string][]*authority
}

func newMasterFile(name string) *masterFile {
	return &masterFile{
		file:    name,
		ips:     map[string][]*authority{},
		domains: map[string][]*authority{},
	}
}

func (m *masterFile) write() error {
	fi, err := ioutil.TempFile("", path.Base(m.file))
	if err != nil {
		return err
	}
	for _, auth := range m.records {
		if err := auth.write(fi); err != nil {
			return err
		}
	}
	tmp := fi.Name()
	if err := fi.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, m.file)
}

func (m *masterFile) updateIP(domain string, ip string) {
	for _, auth := range m.domains[domain] {
		auth.updateIP(domain, ip)
	}
}

func (m *masterFile) process(tokens <-chan *dns.Token) error {
	var auth *authority
	for tok := range tokens {
		if tok.Error != nil {
			return tok.Error
		}
		hdr := tok.RR.Header()
		switch hdr.Class {
		case dns.ClassINET:
			switch hdr.Rrtype {
			case dns.TypeSOA:
				if soa, ok := tok.RR.(*dns.SOA); ok {
					auth = m.newAuthority(soa.Hdr.Name)
				} else {
					return fmt.Errorf("mismatched Rrtype SOA and type %T", tok.RR)
				}
			default:
			}
		default:
			// only handle INET class
			continue
		}
		if auth == nil {
			return fmt.Errorf("missing SOA resource record")
		}
		auth.add(tok)
	}
	return nil
}

func (m *masterFile) newAuthority(domain string) *authority {
	dr := newAuthority(domain)
	dr.master = m
	m.records = append(m.records, dr)
	return dr
}

type authority struct {
	domain  string
	master  *masterFile
	dirty   bool
	records []*dns.Token
	ips     map[string][]*dns.Token
	names   map[string][]*dns.Token
}

func newAuthority(domain string) *authority {
	return &authority{
		domain: domain,
		ips:    map[string][]*dns.Token{},
		names:  map[string][]*dns.Token{},
	}
}

func (y *authority) write(w io.Writer) error {
	if y.dirty {
		soa, ok := y.records[0].RR.(*dns.SOA)
		if !ok {
			return fmt.Errorf("first record should be SOA %q: %T", y.domain, y.records[0])
		}
		soa.Serial = soa.Serial + 1
	}
	for _, tok := range y.records {
		if tok.Error != nil {
			return tok.Error
		}
		if _, err := fmt.Fprintf(w, "%s %s\n", tok.RR.String(), tok.Comment); err != nil {
			return err
		}
	}
	return nil
}

func (y *authority) updateIP(domain string, ip string) {
	ipa := net.ParseIP(ip)
	for _, tok := range y.names[domain] {
		rec := getRecord(tok)
		if rec.ip != ip && rec.ip != "" && ip != "" {
			y.dirty = true
			y.remove(rec, tok)
			if a, ok := tok.RR.(*dns.A); ok {
				a.A = ipa
			}
			if aaaa, ok := tok.RR.(*dns.AAAA); ok {
				aaaa.AAAA = ipa
			}
			rec = getRecord(tok)
			y.update(rec, tok)
		}
	}
}

func (y *authority) add(tok *dns.Token) {
	y.records = append(y.records, tok)
	r := getRecord(tok)
	y.update(r, tok)
}

func (y *authority) remove(r record, tok *dns.Token) {
	if r.ip != "" {
		// TODO remove ips
	}
	// TODO remove domains
}

func (y *authority) update(r record, tok *dns.Token) {
	if r.ip != "" {
		y.ips[r.ip] = append(y.ips[r.ip], tok)
		y.master.ips[r.ip] = append(y.master.ips[r.ip], y)
		y.master.parent.ips[r.ip] = append(y.master.parent.ips[r.ip], y.master)
	}
	y.names[r.name] = append(y.names[r.name], tok)
	y.master.domains[r.name] = append(y.master.domains[r.name], y)
	y.master.parent.domains[r.name] = append(y.master.parent.domains[r.name], y.master)
}

func getRecord(tok *dns.Token) record {
	hdr := tok.RR.Header()
	r := record{name: hdr.Name}
	switch hdr.Class {
	case dns.ClassINET:
		switch hdr.Rrtype {
		case dns.TypeA:
			if a, ok := tok.RR.(*dns.A); ok {
				r.ip = a.A.String()
			}
		case dns.TypeAAAA:
			if a, ok := tok.RR.(*dns.AAAA); ok {
				r.ip = a.AAAA.String()
			}
		default:
		}
	default:
	}
	return r
}
