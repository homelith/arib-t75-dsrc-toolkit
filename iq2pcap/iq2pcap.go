//------------------------------------------------------------------------------
// iq2pcap.go
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// MIT License
//
// Copyright (c) 2021 homelith
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
	"bufio"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type Complex8 struct {
	i int8
	q int8
}

const (
	C8_CHUNK_SIZE     = 1024
	C8CHAN_QUEUE_SIZE = 16
	SQUARK_INTERVAL   = 10000000
)

// read bytes from bufio.Reader and pack into Complex8 c8ChanOut
// issue (*os.File).Close() to graceful stop reading and trigger stop message via doneChanOut
// if reader reach EOF, this module trigger stop message both doneChanMain and doneChanOut
func c8Source(wg *sync.WaitGroup, f *os.File) (eofChan chan struct{}, c8ChanOut chan []Complex8) {
	eofChan = make(chan struct{})
	c8ChanOut = make(chan []Complex8, C8CHAN_QUEUE_SIZE)
	reader := bufio.NewReaderSize(f, C8_CHUNK_SIZE*16)
	wg.Add(1)
	go func() {
		phase := 0
		sample := Complex8{}
		count := 0
		for {
			chunk := []Complex8{}

			// read input up to sizeof(struct Complex8) * C8_CHUNK_SIZE
			buf := make([]byte, C8_CHUNK_SIZE*2)
			n, err := reader.Read(buf)
			if err != nil {
				if err == io.EOF {
					log.Print("c8Source : input reader reached EOF or encountered some i/o error\n")
					log.Printf("c8Source : %d samples processed before closing\n", count)
					eofChan <- struct{}{}
				} else {
					log.Print("c8Source : input file closed\n")
					log.Printf("c8Source : %d samples processed before closing\n", count)
				}
				c8ChanOut <- []Complex8{}
				wg.Done()
				return
			}

			// repack bytes into Complex8 struct array
			for idx := 0; idx < n; idx++ {
				if phase == 0 {
					sample.i = int8(buf[idx])
					phase = 1
				} else {
					sample.q = int8(buf[idx])
					chunk = append(chunk, sample)
					count++
					if count%SQUARK_INTERVAL == 0 {
						log.Printf("c8Source : %d samples processed\n", count)
					}
					phase = 0
				}
			}

			// send array to channel
			if len(chunk) != 0 {
				c8ChanOut <- chunk
			}
		}
	}()
	return eofChan, c8ChanOut
}

// duplicate complex8 channel into two
func c8Tee(wg *sync.WaitGroup, c8ChanIn chan []Complex8) (c8ChanOutA chan []Complex8, c8ChanOutB chan []Complex8) {
	c8ChanOutA = make(chan []Complex8, C8CHAN_QUEUE_SIZE)
	c8ChanOutB = make(chan []Complex8, C8CHAN_QUEUE_SIZE)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			in := <-c8ChanIn
			if len(in) == 0 {
				// zero length slice means system shutdown
				c8ChanOutA <- []Complex8{}
				c8ChanOutB <- []Complex8{}
				log.Print("c8Tee : received shutdown message\n")
				return
			} else {
				// non-zero length slice include input signals
				l := len(in)
				outA := make([]Complex8, l)
				copy(outA, in)
				c8ChanOutA <- outA
				outB := make([]Complex8, l)
				copy(outB, in)
				c8ChanOutB <- outB
			}
		}
	}()
	return c8ChanOutA, c8ChanOutB
}

// consume all complex8 channel and do nothing
func c8Sink(wg *sync.WaitGroup, c8ChanIn chan []Complex8) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			in := <-c8ChanIn
			if len(in) == 0 {
				// zero length slice means system shutdown
				log.Print("c8Sink : received shutdown message\n")
				return
			}
		}
	}()
}

func main() {
	var err error

	// parse args
	strPcap := flag.String("w", "", "output pcap filename")
	flag.Parse()

	// show settings
	log.Print("#### iq2pcap ####\n")

	// open output pcap if specified
	var hPcap *os.File
	var writer *pcapgo.Writer
	if *strPcap != "" {
		hPcap, err = os.Create(*strPcap)
		if err != nil {
			log.Fatal(err)
		}
		defer hPcap.Close()

		writer = pcapgo.NewWriter(hPcap)
		// write pcap header
		writer.WriteFileHeader(65536, layers.LinkTypeNull)
	}

	// prepare stdin reader and waitgroup
	wg := &sync.WaitGroup{}

	// run worker goroutines
	eofChan, c8ChanSrc2Tee := c8Source(wg, os.Stdin)
	c8ChanTee2SinkA, c8ChanTee2SinkB := c8Tee(wg, c8ChanSrc2Tee)
	c8Sink(wg, c8ChanTee2SinkA)
	c8Sink(wg, c8ChanTee2SinkB)

	// wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigChan:
		log.Print("main : interrupt signal received\n")
		break
	case <-eofChan:
		log.Print("main : c8Source requested main thread shutdown\n")
		break
	}

	// notify stop message to goroutines and wait for join
	os.Stdin.Close()
	wg.Wait()
	log.Print("main : all goroutines stopped\n")
}
