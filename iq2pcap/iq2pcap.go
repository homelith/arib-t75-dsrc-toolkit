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
	"math"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/alecthomas/units"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	C8_CHUNK_SIZE     = 1024
	C8CHAN_QUEUE_SIZE = 16
	SQUARK_INTERVAL   = 10000000
)

type Complex8 struct {
	i int8
	q int8
}

// custom string flag definition supporting multiple assignment of same flags
// (e.g. '-d +5M:upper.pcap -d -5M:lower.pcap')
type strFlagMulti []string

func (v *strFlagMulti) String() string {
	return strings.Join([]string(*v), " ")
}
func (s *strFlagMulti) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// GCD (greatest common divisor) and LCM (least common multiple)
func gcd(a int64, b int64) int64 {
	for b != 0 {
		t := b
		b = a % b
		a = t
	}
	return a
}
func lcm(a int64, b int64) int64 {
	return a * b / gcd(a, b)
}

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

// shifting center frequency of signal by multiplying with specified frequency sinusoid
func c8Shift(wg *sync.WaitGroup, c8ChanIn chan []Complex8, sampleRate int64, detectRate int64) (c8ChanOut chan []Complex8) {
	c8ChanOut = make(chan []Complex8, C8CHAN_QUEUE_SIZE)

	// generate sinusoid lookup table
	absDetectRate := detectRate
	if absDetectRate < 0 {
		absDetectRate = -absDetectRate
	}
	tableSize := lcm(sampleRate, absDetectRate) / absDetectRate
	log.Printf("c8shift : sinusoid lookup table size is set to %d", tableSize)
	sinusoidTable := make([]Complex8, tableSize)
	for i := int64(0); i < tableSize; i++ {
		rad := float64(-detectRate) / float64(sampleRate) * 2.0 * math.Pi * float64(i)
		sinusoidTable[i].i = int8(math.Round(126.0 * math.Cos(rad)))
		sinusoidTable[i].q = int8(math.Round(126.0 * math.Sin(rad)))
	}

	// main worker
	wg.Add(1)
	go func() {
		defer wg.Done()
		phase := int64(0)
		for {
			in := <-c8ChanIn
			if len(in) == 0 {
				// zero length slice means system shutdown
				c8ChanOut <- []Complex8{}
				log.Print("c8Shift : received shutdown message\n")
				return
			} else {
				// multiply input signal with sinusoid table
				out := make([]Complex8, len(in))
				for i := 0; i < len(in); i++ {
					// complex multiply
					out[i].i = int8(int16(in[i].i)*int16(sinusoidTable[phase].i) - int16(in[i].q)*int16(sinusoidTable[phase].q))
					out[i].q = int8(int16(in[i].i)*int16(sinusoidTable[phase].q) + int16(in[i].q)*int16(sinusoidTable[phase].i))

					// phase increment and wrap around
					phase++
					if phase == tableSize {
						phase = 0
					}
				}
				c8ChanOut <- out
			}
		}
	}()
	return c8ChanOut
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
	log.Print("#### iq2pcap ####\n")

	// parse args
	detectorStrAry := strFlagMulti{}
	flag.Var(&detectorStrAry, "d", "detector params (e.g. '-d +5M:plus_5M.pcap -d -5M:minus_5M.pcap')")
	sampleRateStr := flag.String("s", "20M", "sampling rate (e.g. '-s 20M') (default: 20M)")
	flag.Parse()

	// parse sampling rate
	unitMap := units.MakeUnitMap("", "", 1000)
	sampleRate, err := units.ParseUnit(*sampleRateStr, unitMap)
	if err != nil {
		log.Fatalf("main : error on parsing '-s %s' as sampling rate\n", *sampleRateStr)
	}
	log.Printf("main : sampling rate set to %d Hz\n", sampleRate)

	// parse detector params
	if len(detectorStrAry) == 0 {
		log.Fatal("main : you must specify at least one '-d' param\n")
	}
	type detectorParam struct {
		detectRate int64
		handlePcap *os.File
		writerPcap *pcapgo.Writer
	}
	detectorParamAry := []detectorParam{}
	for idx, str := range detectorStrAry {
		// extract colon-seperated substring
		param := detectorParam{}
		subStrAry := strings.Split(str, ":")
		if len(subStrAry) != 2 {
			log.Fatalf("main : error on break '-s %s' into two colon-seperated subparams\n", str)
		}

		// parse detection rate
		rate, err := units.ParseUnit(subStrAry[0], unitMap)
		if err != nil {
			log.Fatalf("main : error on parsing '-s %s' detector rate\n", str)
		}
		param.detectRate = rate

		// open pcap file
		handle, err := os.Create(subStrAry[1])
		if err != nil {
			log.Fatalf("main : error opening pcapfile (%v)\n", err)
		}
		param.handlePcap = handle
		writer := pcapgo.NewWriter(handle)
		param.writerPcap = writer

		// register struct
		detectorParamAry = append(detectorParamAry, param)
		log.Printf("main : %d th detector will focus on offset %d Hz\n", idx, param.detectRate)
		log.Printf("main : %d th detector output is written on %s\n", idx, subStrAry[1])

		// write pcap header
		writer.WriteFileHeader(65536, layers.LinkTypeNull)
	}

	// register pcapfile cleanup process
	defer func() {
		for _, param := range detectorParamAry {
			param.handlePcap.Close()
		}
	}()

	// prepare stdin reader and waitgroup
	wg := &sync.WaitGroup{}

	// run worker goroutines
	eofChan, c8ChanTeeThrough := c8Source(wg, os.Stdin)
	for i := 0; i < len(detectorParamAry)-1; i++ {
		c8ChanTeeDrop := make(chan []Complex8)
		c8ChanTeeDrop, c8ChanTeeThrough = c8Tee(wg, c8ChanTeeThrough)
		c8ChanShift2Sink := c8Shift(wg, c8ChanTeeDrop, sampleRate, detectorParamAry[i].detectRate)
		c8Sink(wg, c8ChanShift2Sink)
	}
	c8ChanShift2Sink := c8Shift(wg, c8ChanTeeThrough, sampleRate, detectorParamAry[len(detectorParamAry)-1].detectRate)
	c8Sink(wg, c8ChanShift2Sink)

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
