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
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// globals
var MdsKeySlot [6]uint16
var MdsKeySlotUsing = false
var MdsKeySlotIdx = 0
var MdsKeySlotNum = 0

//------------------------------------------------------------------------------
// implements
//------------------------------------------------------------------------------

func parse_fcmc(pkt_fcmc []byte) bool {

	var csum uint16
	var ref uint16
	var i int
	var j int

	// reset LID store for descrambling
	MdsKeySlotIdx = 0
	MdsKeySlotNum = 0
	MdsKeySlotUsing = false

	// calc CRC16 (1+x^5+x^12+x16) based on octet 4 to 55
	if len(pkt_fcmc) < 58 {
		fmt.Printf("calc CRC : packet is shorter than 58 byte, skipping.\n")
		return true
	}

	csum = 0xffff
	for i = 4; i < 56; i++ {
		csum ^= uint16(pkt_fcmc[i])
		for j = 0; j < 8; j++ {
			if csum&0x0001 == 0x0001 {
				csum = (csum >> 1) ^ 0x8408
			} else {
				csum = (csum >> 1)
			}
		}
	}
	csum = ^csum
	ref = (uint16(pkt_fcmc[57]) << 8) | (uint16(pkt_fcmc[56]))

	if csum != ref {
		fmt.Printf("calc CRC : calculated 0x%04x and reference 0x%04x differs.\n", csum, ref)
	} else {
		fmt.Printf("calc CRC : calculated 0x%04x and reference 0x%04x matched.\n", csum, ref)
	}

	// parse SC (IMI + API)
	if pkt_fcmc[9]&0x01 == 0x00 {
		fmt.Printf("parse IMI : standard procedure (0x00)\n")
	} else {
		fmt.Printf("parse IMI : simplified procedure (0x01), not supported then abort processing.\n")
		return true
	}

	for i = 0; i < 6; i++ {
		var ext uint8
		var aid uint8
		ext = pkt_fcmc[10+i] & 0x01
		aid = (pkt_fcmc[10+i] >> 3) & 0x1f

		fmt.Printf("API #%d slot : type == ", i+1)

		switch aid {
		case 0:
			fmt.Printf("'System'")
		case 1:
			fmt.Printf("'ISO14906 Application'")
		case 2:
			fmt.Printf("'ISO-DSRC Application'")
		case 3:
			fmt.Printf("'ISO-DSRC Application'")
		case 4:
			fmt.Printf("'ISO-DSRC Application'")
		case 5:
			fmt.Printf("'ISO-DSRC Application'")
		case 6:
			fmt.Printf("'ISO-DSRC Application'")
		case 7:
			fmt.Printf("'ISO-DSRC Application'")
		case 8:
			fmt.Printf("'ISO-DSRC Application'")
		case 9:
			fmt.Printf("'ISO-DSRC Application'")
		case 10:
			fmt.Printf("'ISO-DSRC Application'")
		case 11:
			fmt.Printf("'ISO-DSRC Application'")
		case 12:
			fmt.Printf("'ISO-DSRC Application'")
		case 13:
			fmt.Printf("'ISO-DSRC Application'")
		case 14:
			fmt.Printf("'Multi-purpose Toll Collection system (ETC)'")
		case 15:
			fmt.Printf("'ISO-DSRC Application'")
		case 16:
			fmt.Printf("'Driving support system'")
		case 17:
			fmt.Printf("'Multi-purpose information system'")
		case 18:
			fmt.Printf("'ISO-DSRC Application'")
		case 19:
			fmt.Printf("'ISO-DSRC Application'")
		case 20:
			fmt.Printf("'ISO-DSRC Application'")
		case 21:
			fmt.Printf("'ISO-DSRC Application'")
		case 29:
			fmt.Printf("'ISO-DSRC Application'")
		case 30:
			fmt.Printf("'ISO-DSRC Application'")
		default:
			fmt.Printf("'unknown'")
		}

		if ext == 0x00 {
			fmt.Printf("\n")
		} else {
			fmt.Printf(", Last Item\n")
			break
		}
	}

	// parse SCI (CI + LID)
	var cm uint8
	var sln uint8
	cm = pkt_fcmc[7] & 0x01
	sln = ((pkt_fcmc[7] >> 1) & 0x07) + 0x01

	if cm == 0x00 {
		fmt.Printf("parse FSI : Full Duplex, %d x 2 slot occupied\n", sln)
		sln = sln * 2
	} else {
		fmt.Printf("parse FSI : Half Duplex, %d slot occupied\n", sln)
	}

	for i = 0; i < int(sln); i++ {
		var si uint8
		var bcast uint8
		si = pkt_fcmc[16+(i*5)] & 0x03
		bcast = pkt_fcmc[17+(i*5)] & 0x01

		if cm == 0x00 {
			if i%2 == 0 {
				fmt.Printf("SCI #%d downlink : ", int(i/2))
			} else {
				fmt.Printf("SCI #%d uplink : ", int(i/2))
			}
		} else {
			fmt.Printf("SCI #%d : ", i)
		}
		if si == 0x00 {
			var dri uint8
			var st uint8
			var dr uint8
			dri = (pkt_fcmc[16+(i*5)] >> 2) & 0x03
			st = (pkt_fcmc[16+(i*5)] >> 4) & 0x07
			dr = (pkt_fcmc[16+(i*5)] >> 7) & 0x01

			fmt.Printf("type == 'MDS'")

			if dri == 0x00 {
				fmt.Printf(", ask modulation")
			} else if dri == 0x03 {
				fmt.Printf(", pi/4 qpsk modulation")
			} else {
				fmt.Printf(", unknown modulation")
			}

			if st == 0x00 {
				fmt.Printf(", priority data channel")
			} else if st == 0x01 {
				fmt.Printf(", idle data channel")
			} else if st == 0x06 {
				fmt.Printf(", empty data channel")
			} else if st == 0x07 {
				fmt.Printf(", standard data channel")
			} else {
				fmt.Printf(", unknown data channel")
			}

			if dr == 0x00 {
				fmt.Printf(", downlink")
			} else {
				fmt.Printf(", uplink")
			}

			if dri == 0x00 && st != 0x06 {
				if bcast == 0x01 {
					fmt.Printf(", LID 0x%02x (bcast)", pkt_fcmc[17+i*5])
					MdsKeySlot[MdsKeySlotNum] = 0x0000
					fmt.Printf(", set 0x0000 to MDS Key[%d]", MdsKeySlotNum)
				} else {
					fmt.Printf(", LID 0x%02x%02x%02x%02x", pkt_fcmc[17+i*5], pkt_fcmc[18+i*5], pkt_fcmc[19+i*5], pkt_fcmc[20+i*5])
					MdsKeySlot[MdsKeySlotNum] = ^((uint16(pkt_fcmc[18+i*5]) << 8) | uint16(pkt_fcmc[17+i*5]))
					fmt.Printf(", set 0x%04x to MDS Key[%d]", MdsKeySlot[MdsKeySlotNum], MdsKeySlotNum)
				}
				MdsKeySlotNum++
			}
		} else if si == 0x01 {
			fmt.Printf("type == 'WCNS'")
		} else if si == 0x03 {
			fmt.Printf("type == 'ACTS'")
		} else {
			fmt.Printf("type == 'Reserved SI'")
		}

		fmt.Printf("\n")
	}
	return true
}

func dscr_mdc(pkt_mdc []byte) {
	var i int
	var j int
	var b byte

	// check if there is a decode key available
	if MdsKeySlotIdx == MdsKeySlotNum {
		fmt.Printf("descramble : no more MDS Key available, skipped descrambling\n")
		return
	}

	var shiftreg uint16
	shiftreg = MdsKeySlot[MdsKeySlotIdx]

	var dscr_end_count int
	var csum_enabled bool

	if len(pkt_mdc) < 69 {
		fmt.Printf("descramble : packet is shorter than 69 octet, skipped descrambling.\n")
		return
	} else if len(pkt_mdc) < 71 {
		fmt.Printf("descramble : packet is shorter than 71 octet, checksum disabled.\n")
		dscr_end_count = len(pkt_mdc)
		csum_enabled = false
	} else {
		dscr_end_count = 71
		csum_enabled = true
	}

	fmt.Printf("descramble : using MDS Key[%d] = '0x%04x'\n", MdsKeySlotIdx, MdsKeySlot[MdsKeySlotIdx])

	// descramble from octet 4 to dscr_end_count
	for i = 4; i < dscr_end_count; i++ {
		var tip byte
		for j = 0; j < 8; j++ {
			tip = (tip >> 1) & 0x7f
			if shiftreg&0x0001 == 0x0001 {
				tip = tip | 0x80
			}
			if ((shiftreg&0x8000)>>15)^((shiftreg&0x2000)>>13)^((shiftreg&0x0010)>>4)^(shiftreg&0x0001) == 0x0001 {
				shiftreg = 0x8000 | ((shiftreg >> 1) & 0x7fff)
			} else {
				shiftreg = (shiftreg >> 1) & 0x7fff
			}
		}
		pkt_mdc[i] = pkt_mdc[i] ^ tip
	}

	// dump altered bin
	for i, b = range pkt_mdc {
		fmt.Printf("%02x ", b)
		if i%16 == 15 {
			fmt.Printf("\n")
		}
	}
	fmt.Printf("\n")

	// calc CRC16 (1+x^5+x^12+x16) based on octet 2 to 68
	var csum uint16
	var ref uint16
	csum = 0xffff
	for i = 2; i < (dscr_end_count - 2); i++ {
		csum ^= uint16(pkt_mdc[i])
		for j = 0; j < 8; j++ {
			if csum&0x0001 == 0x0001 {
				csum = (csum >> 1) ^ 0x8408
			} else {
				csum = (csum >> 1)
			}
		}
	}
	csum = ^csum

	if csum_enabled {
		ref = (uint16(pkt_mdc[70]) << 8) | (uint16(pkt_mdc[69]))
		if csum != ref {
			fmt.Printf("calc CRC : calculated 0x%04x and reference 0x%04x differs.\n", csum, ref)
			MdsKeySlotIdx++
			MdsKeySlotUsing = false
		} else {
			fmt.Printf("calc CRC : calculated 0x%04x and reference 0x%04x matched.\n", csum, ref)
			MdsKeySlotUsing = true
			//MdsKeySlot[MdsKeySlotIdx] = shiftreg
		}
	} else {
		fmt.Printf("calc CRC : calculated 0x%04x and auto matching disabled\n", csum)
		MdsKeySlotUsing = true
		//MdsKeySlot[MdsKeySlotIdx] = shiftreg
	}
}

func main() {
	var err error

	// parse args
	flag.Parse()
	if len(flag.Args()) < 2 {
		log.Println("usage : ./mdcdscr {input.pcap} {output.pcap}")
		os.Exit(0)
	}

	// show settings
	fmt.Printf("#### MDC descrambler ####\n")
	fmt.Printf("descramble MDC payload from FCMC keys\n")
	fmt.Printf("--------------------------------\n")

	// open input pcap
	var file_in *os.File
	file_in, err = os.Open(flag.Args()[0])
	if err != nil {
		log.Fatal(err)
	}
	defer file_in.Close()

	var reader *pcapgo.Reader
	reader, err = pcapgo.NewReader(file_in)

	// open output pcap
	var file_out *os.File
	file_out, err = os.Create(flag.Args()[1])
	if err != nil {
		log.Fatal(err)
	}
	defer file_out.Close()

	var writer *pcapgo.Writer
	writer = pcapgo.NewWriter(file_out)
	writer.WriteFileHeader(65536, layers.LinkTypeNull)

	// process packet
	var num = 1

	var pkt []byte
	var ci gopacket.CaptureInfo

	for {
		// read next packet
		pkt, ci, err = reader.ReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("error : ", err)
			continue
		}

		// identify downlink / uplink from timestamp
		var is_dl bool
		if ci.Timestamp.Nanosecond()%10000 == 0 {
			is_dl = true
		} else {
			is_dl = false
		}

		// show number of try
		if is_dl {
			fmt.Printf("---- #%d packet (len=%d, time=%.6f, downlink) ----\n", num, len(pkt), float64(ci.Timestamp.UnixNano())/1000000000.0)
		} else {
			fmt.Printf("---- #%d packet (len=%d, time=%.6f, uplink) ----\n", num, len(pkt), float64(ci.Timestamp.UnixNano())/1000000000.0)
		}
		num++

		// dumpbin
		var b byte
		var i int
		for i, b = range pkt {
			fmt.Printf("%02x ", b)
			if i%16 == 15 {
				fmt.Printf("\n")
			}
		}
		fmt.Printf("\n")

		var crc_matched bool
		crc_matched = true

		if len(pkt) < 2 {
			fmt.Printf("parse UW : pkt under 2bytes, skipping.\n")
		} else {
			var uw_hiword = binary.BigEndian.Uint16(pkt[0:2])
			if uw_hiword == 0xd815 {
				if len(pkt) < 4 {
					fmt.Printf("parse UW : pkt under 4bytes, skipping.\n")
				} else {
					// find ASK UW1 (FCMC) and get MDC descramble key from LID
					var uw = binary.BigEndian.Uint32(pkt[0:4])
					if uw == 0xd815d27c {
						fmt.Printf("parse UW : ASK UW1 (0x%x) detected.\n", uw)
						crc_matched = parse_fcmc(pkt)
					} else {
						fmt.Printf("parse UW : unknown (0x%x) UW detected, skipping.\n", uw)
					}
				}
			} else if uw_hiword == 0xd27c {
				// find ASK UW2 (MDC downstream) and descramble using available Key List
				fmt.Printf("parse UW : ASK UW2 (0x%x) UW detected.\n", uw_hiword)
				if len(pkt) >= 70 {
					dscr_mdc(pkt)
				}
			} else {
				fmt.Printf("parse UW : unknown (0x%x) UW detected, skipping.\n", uw_hiword)
			}
		}

		fmt.Printf("\n")

		// write pkt
		if crc_matched {
			writer.WritePacket(ci, pkt)
		}
	}
}
