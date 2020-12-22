//------------------------------------------------------------------------------
// mdcdscr.go
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// MIT License
//
// Copyright (c) 2020 homelith
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//------------------------------------------------------------------------------

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

//------------------------------------------------------------------------------
// implements
//------------------------------------------------------------------------------
func main() {
	var err error
	var uplink_offset time.Duration

	// parse args
	var ofs int
	flag.IntVar(&ofs, "o", 0, "uplink pcap offset from downlink pcap in usec")
	flag.Parse()
	if len(flag.Args()) < 3 {
		log.Println("usage : ./ofsmerge -o {uplink_offset} {downlink.pcap} {uplink.pcap} {output.pcap}")
		os.Exit(0)
	}
	uplink_offset = time.Duration(ofs * 1000)

	// show settings
	fmt.Printf("#### pcap offset merger ####\n")
	fmt.Printf(" - generate %s from %s and %s\n", flag.Args()[2], flag.Args()[0], flag.Args()[1])
	fmt.Printf("--------------------------------\n")

	// open input downlink pcap
	var dl_file *os.File
	dl_file, err = os.Open(flag.Args()[0])
	if err != nil {
		log.Fatal(err)
	}
	defer dl_file.Close()

	var dl_reader *pcapgo.Reader
	dl_reader, err = pcapgo.NewReader(dl_file)

	// open input uplink pcap
	var ul_file *os.File
	ul_file, err = os.Open(flag.Args()[1])
	if err != nil {
		log.Fatal(err)
	}
	defer ul_file.Close()

	var ul_reader *pcapgo.Reader
	ul_reader, err = pcapgo.NewReader(ul_file)

	// open output pcap
	var file_out *os.File
	file_out, err = os.Create(flag.Args()[2])
	if err != nil {
		log.Fatal(err)
	}
	defer file_out.Close()

	var writer *pcapgo.Writer
	writer = pcapgo.NewWriter(file_out)
	writer.WriteFileHeader(65536, layers.LinkTypeNull)

	// process packet
	var num = 1

	var dl_pkt []byte
	var dl_ci gopacket.CaptureInfo
	var dl_valid bool
	var ul_pkt []byte
	var ul_ci gopacket.CaptureInfo
	var ul_valid bool

	var pkt []byte
	var ci gopacket.CaptureInfo
	var is_dl bool

	dl_valid = false
	ul_valid = false
	is_dl = true

	for {
		// read next packet
		if dl_valid == false {
			dl_pkt, dl_ci, err = dl_reader.ReadPacketData()
			if err == nil {
				dl_valid = true
			}
		}
		if ul_valid == false {
			ul_pkt, ul_ci, err = ul_reader.ReadPacketData()
			if err == nil {
				ul_valid = true
			}
		}

		// select packet source arrives earlier than another
		if dl_valid == true && ul_valid == true {
			if dl_ci.Timestamp.Before(ul_ci.Timestamp.Add(time.Duration(uplink_offset))) {
				dl_valid = false
				is_dl = true
				pkt = dl_pkt
				ci = dl_ci
				ci.Timestamp = ci.Timestamp.Truncate(10000 * time.Nanosecond)
			} else {
				ul_valid = false
				is_dl = false
				pkt = ul_pkt
				ci = ul_ci
				ci.Timestamp = ci.Timestamp.Add(uplink_offset).Truncate(10000 * time.Nanosecond).Add(5000 * time.Nanosecond)
			}
		} else if dl_valid == true {
			dl_valid = false
			is_dl = true
			pkt = dl_pkt
			ci = dl_ci
			ci.Timestamp = ci.Timestamp.Truncate(10000 * time.Nanosecond)
		} else if ul_valid == true {
			ul_valid = false
			is_dl = false
			pkt = ul_pkt
			ci = ul_ci
			ci.Timestamp = ci.Timestamp.Add(uplink_offset).Truncate(10000 * time.Nanosecond).Add(5000 * time.Nanosecond)
		} else {
			// exit processing when both packet source reaches to EOF
			break
		}

		// show number of try
		if is_dl {
			fmt.Printf("---- #%d packet (len=%d, time=%.6f, downlink) ----\n", num, len(pkt), float64(ci.Timestamp.UnixNano())/1000000000.0)
		} else {
			fmt.Printf("---- #%d packet (len=%d, time=%.6f, uplink) ----\n", num, len(pkt), float64(ci.Timestamp.UnixNano())/1000000000.0)
		}
		num++

		// write packet
		writer.WritePacket(ci, pkt)
	}
}
