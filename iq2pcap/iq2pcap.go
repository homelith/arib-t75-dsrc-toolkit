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
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type MetaData struct {
	startOfPacket bool
}

type Complex8 struct {
	i    int8
	q    int8
	meta *MetaData
}

// read bytes from bufio.Reader and pack into Complex8 c8ChanOut
// Close(reader) to graceful stop reading and trigger stop message via doneChanOut
func c8Source(wg *sync.WaitGroup, reader *bufio.Reader) (chan struct{}, chan Complex8) {
	doneChanOut := make(chan struct{})
	c8ChanOut := make(chan Complex8, 4096)
	wg.Add(1)
	go func() {
		phase := 0
		sample := Complex8{}
		sampleCount := 0
		for {
			b, err := reader.ReadByte()
			if err != nil {
				break
			}
			if phase == 0 {
				sample.i = int8(b)
				phase = 1
			} else {
				sample.q = int8(b)
				c8ChanOut <- sample
				sampleCount++
				phase = 0
			}
		}
		log.Printf("c8Source : %d samples processed before closing\n", sampleCount)
		doneChanOut <- struct{}{}
		wg.Done()
	}()

	return doneChanOut, c8ChanOut
}

// duplicate complex8 channel into two
func c8Tee(wg *sync.WaitGroup, doneChanIn chan struct{}, c8ChanIn chan Complex8) (chan struct{}, chan Complex8, chan struct{}, chan Complex8) {
	doneChanOutA := make(chan struct{})
	c8ChanOutA := make(chan Complex8, 4096)
	doneChanOutB := make(chan struct{})
	c8ChanOutB := make(chan Complex8, 4096)

	wg.Add(1)
	go func() {
		defer wg.Done()
		sampleCount := 0
		running := true

		finalize := func() {
			log.Printf("c8Tee : %d samples processed before closing\n", sampleCount)
			doneChanOutA <- struct{}{}
			doneChanOutB <- struct{}{}
		}

		for {
			select {
			case <-doneChanIn:
				if len(c8ChanIn) == 0 {
					finalize()
					return
				} else {
					running = false
				}
				break
			case sample := <-c8ChanIn:
				c8ChanOutA <- sample
				c8ChanOutB <- sample
				sampleCount++
				if !running && len(c8ChanIn) == 0 {
					finalize()
					return
				}
			}
		}
	}()
	return doneChanOutA, c8ChanOutA, doneChanOutB, c8ChanOutB
}

// consume all complex8 channel and do nothing
func c8Sink(wg *sync.WaitGroup, doneChanIn chan struct{}, c8ChanIn chan Complex8) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		sampleCount := 0
		running := true

		finalize := func() {
			log.Printf("c8Sink : %d samples processed before closing\n", sampleCount)
		}

		for {
			select {
			case <-doneChanIn:
				if len(c8ChanIn) == 0 {
					finalize()
					return
				} else {
					running = false
				}
				break
			case <-c8ChanIn:
				sampleCount++
				if !running && len(c8ChanIn) == 0 {
					finalize()
					return
				}
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
	fmt.Print("#### iq2pcap ####\n")

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
	reader := bufio.NewReader(os.Stdin)

	// run worker goroutines
	doneChanSrc2Tee, c8ChanSrc2Tee := c8Source(wg, reader)
	doneChanTee2SinkA, c8ChanTee2SinkA, doneChanTee2SinkB, c8ChanTee2SinkB := c8Tee(wg, doneChanSrc2Tee, c8ChanSrc2Tee)
	c8Sink(wg, doneChanTee2SinkA, c8ChanTee2SinkA)
	c8Sink(wg, doneChanTee2SinkB, c8ChanTee2SinkB)

	// wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("main : interrupt signal received")

	// notify stop message to goroutines and wait for join
	os.Stdin.Close()
	wg.Wait()
	log.Println("main : all goroutines stopped, exitting..")
}
