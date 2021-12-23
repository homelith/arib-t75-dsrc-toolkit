################################################################################
# Makefile for go project
################################################################################

TARGET   := ofsmerge
SRCS     := ofsmerge.go

.PHONY: default run

################################################################################

default : run

run : $(TARGET)
	@if [ ! -e "downlink.pcap" ] ; then echo "error : downlink.pcap not found" ; exit 1 ; fi
	@if [ ! -e "uplink.pcap" ] ; then echo "error : uplink.pcap not found" ; exit 1 ; fi
	./$(TARGET) -o 0 downlink.pcap uplink.pcap output.pcap

$(TARGET) : $(SRCS)
	go mod tidy
	go fmt $(SRCS)
	GOOS=linux GOARCH=amd64 go build -o $(TARGET) $(SRCS)
	chmod +x $@

clean:
	rm -f go.sum $(TARGET)
