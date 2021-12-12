################################################################################
# Makefile for go project
################################################################################

TARGET   := iq2pcap
SRCS     := iq2pcap.go

.PHONY: default run

################################################################################

default : test

test : $(TARGET)
	@if [ ! -e "input.bin" ] ; then echo "error : input.bin not found" ; exit 1 ; fi
	./$(TARGET) -s 20M -d +5M:upper.pcap -d -5M:lower.pcap < input.bin

$(TARGET) : $(SRCS)
	go mod tidy
	go fmt $(SRCS)
	GOOS=linux GOARCH=amd64 go build -o $(TARGET) $(SRCS)
	chmod +x $@

clean:
	rm -f go.sum upper.pcap lower.pcap $(TARGET)
