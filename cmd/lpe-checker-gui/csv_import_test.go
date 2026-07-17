package main

import (
	"bytes"
	"strings"
	"testing"

	htmlreport "lpe-checker/internal/report"
)

func TestParseCSVHostsNormalAndHeader(t *testing.T) {
	input := "host,port,user,password\n192.0.2.85,22,root,example-password\n198.51.100.219,53222,admin,example-password-2\n"
	hosts, skipped, err := parseCSVHosts(strings.NewReader(input))
	if err != nil || skipped != 0 || len(hosts) != 2 {
		t.Fatalf("unexpected result: hosts=%+v skipped=%d err=%v", hosts, skipped, err)
	}
	if hosts[1].Host != "198.51.100.219" || hosts[1].Port != 53222 || hosts[1].User != "admin" {
		t.Fatalf("unexpected second host: %+v", hosts[1])
	}
}

func TestGeneratedHostCSVTemplateRoundTripsThroughImporter(t *testing.T) {
	var template bytes.Buffer
	if err := htmlreport.GenerateHostCSVTemplate(&template); err != nil {
		t.Fatal(err)
	}
	hosts, skipped, err := parseCSVHosts(bytes.NewReader(template.Bytes()))
	if err != nil || skipped != 0 || len(hosts) != 0 {
		t.Fatalf("empty generated template was not import-compatible: hosts=%+v skipped=%d err=%v", hosts, skipped, err)
	}

	filled := append(append([]byte{}, template.Bytes()...), []byte("example.org,22,root,example-password\n")...)
	hosts, skipped, err = parseCSVHosts(bytes.NewReader(filled))
	if err != nil || skipped != 0 || len(hosts) != 1 || hosts[0].Host != "example.org" || hosts[0].Port != 22 || hosts[0].User != "root" || hosts[0].Password != "example-password" {
		t.Fatalf("filled generated template did not round trip: hosts=%+v skipped=%d err=%v", hosts, skipped, err)
	}
}

func TestParseCSVHostsToleranceDefaultsAndQuotedPassword(t *testing.T) {
	input := "\n主机,端口,用户名,密码\ngood.example,,root,\"example,password\"\ntoo,few,fields\nbad.example,not-a-port,root,example-password-invalid\nother.example,2222,admin,example-password-2\n"
	hosts, skipped, err := parseCSVHosts(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 3 {
		t.Fatalf("skipped=%d; want 3", skipped)
	}
	if len(hosts) != 2 || hosts[0].Port != 22 || hosts[0].Password != "example,password" || hosts[1].Port != 2222 {
		t.Fatalf("unexpected parsed hosts: %+v", hosts)
	}
}

func TestParseCSVHostsWithoutHeader(t *testing.T) {
	hosts, skipped, err := parseCSVHosts(strings.NewReader("example.org,22,root,example-password\n"))
	if err != nil || skipped != 0 || len(hosts) != 1 || hosts[0].Host != "example.org" {
		t.Fatalf("unexpected result: hosts=%+v skipped=%d err=%v", hosts, skipped, err)
	}
}
