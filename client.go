// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package main

import (
	"log"

	g "github.com/gosnmp/gosnmp"
)

func main() {

	// Default is a pointer to a GoSNMP struct that contains sensible defaults
	// eg port 161, community public, etc
	g.Default.Target = "192.168.31.181"
	g.Default.Community = "vas"
	g.Default.Port = 162
	g.Default.Version = g.Version1

	err := g.Default.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer g.Default.Conn.Close()

	pdu := g.SnmpPDU{
		Name:  "1.3.6.1.2.1.1.6",
		Type:  g.OctetString,
		Value: `{"level":"INFO","timestamp":"2024-11-05 15:29:32.672","file":"middleware/logging.go:69","msg":"49.344496ms   | 127.0.0.1    | POST /api/risk/vulns | {code: 200, message: }"}`,
	}

	trap := g.SnmpTrap{
		Variables:    []g.SnmpPDU{pdu},
		Enterprise:   ".1.3.6.1.6.3.1.1.5.1",
		AgentAddress: "127.0.0.1",
		GenericTrap:  0,
		SpecificTrap: 0,
		Timestamp:    300,
	}

	_, err = g.Default.SendTrap(trap)
	if err != nil {
		log.Fatalf("SendTrap() err: %v", err)
	}
}
