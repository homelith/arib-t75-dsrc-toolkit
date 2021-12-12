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

// read bytes from bufio.Reader and pack into Complex8 c8ChanOut
// Close(reader) to graceful stop reading and trigger stop message via doneChanOut
func c8Source(wg *sync.WaitGroup, reader *bufio.Reader) (chan struct{}, chan struct{}, chan []Complex8) {
	doneChanMain := make(chan struct{})
	doneChanOut := make(chan struct{})
	c8ChanOut := make(chan []Complex8, 16)
	wg.Add(1)
	go func() {
		phase := 0
		sample := Complex8{}
		sampleCount := 0
		for {
			buf := make([]byte, 2048)
			sampleAry := []Complex8{}
			n, err := reader.Read(buf)
			if err != nil {
				if err == io.EOF {
					log.Print("c8Source : input reader reached EOF\n")
					log.Printf("c8Source : %d samples processed before closing\n", sampleCount)
					doneChanMain <- struct{}{}
					doneChanOut <- struct{}{}
				} else {
					log.Print("c8Source : input file closed\n")
					log.Printf("c8Source : %d samples processed before closing\n", sampleCount)
					doneChanOut <- struct{}{}
				}
				wg.Done()
				return
			}
			for idx := 0; idx < n; idx++ {
				if phase == 0 {
					sample.i = int8(buf[idx])
					phase = 1
				} else {
					sample.q = int8(buf[idx])
					sampleAry = append(sampleAry, sample)
					sampleCount++
					phase = 0
				}
			}
			if len(sampleAry) != 0 {
				c8ChanOut <- sampleAry
			}
		}
	}()

	return doneChanMain, doneChanOut, c8ChanOut
}

// duplicate complex8 channel into two
func c8Tee(wg *sync.WaitGroup, doneChanIn chan struct{}, c8ChanIn chan []Complex8) (chan struct{}, chan []Complex8, chan struct{}, chan []Complex8) {
	doneChanOutA := make(chan struct{})
	c8ChanOutA := make(chan []Complex8, 16)
	doneChanOutB := make(chan struct{})
	c8ChanOutB := make(chan []Complex8, 16)

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
			case in := <-c8ChanIn:
				l := len(in)
				outA := make([]Complex8, l)
				copy(outA, in)
				c8ChanOutA <- outA
				outB := make([]Complex8, l)
				copy(outB, in)
				c8ChanOutB <- outB
				sampleCount += l

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
func c8Sink(wg *sync.WaitGroup, doneChanIn chan struct{}, c8ChanIn chan []Complex8) {
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
			case in := <-c8ChanIn:
				sampleCount += len(in)
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
	reader := bufio.NewReader(os.Stdin)

	// run worker goroutines
	doneChanMain, doneChanSrc2Tee, c8ChanSrc2Tee := c8Source(wg, reader)
	doneChanTee2SinkA, c8ChanTee2SinkA, doneChanTee2SinkB, c8ChanTee2SinkB := c8Tee(wg, doneChanSrc2Tee, c8ChanSrc2Tee)
	c8Sink(wg, doneChanTee2SinkA, c8ChanTee2SinkA)
	c8Sink(wg, doneChanTee2SinkB, c8ChanTee2SinkB)

	// wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigChan:
		log.Print("main : interrupt signal received\n")
		break
	case <-doneChanMain:
		log.Print("main : c8Source requested main thread shutdown\n")
		break
	}

	// notify stop message to goroutines and wait for join
	os.Stdin.Close()
	wg.Wait()
	log.Print("main : all goroutines stopped\n")
}
