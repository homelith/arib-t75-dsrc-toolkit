################################################################################
# Makefile for go project
################################################################################

TARGET   := mdcdscr
SRCS     := mdcdscr.go

.PHONY: default run

################################################################################

default : run

run : $(TARGET)
	@if [ ! -e "input.pcap" ] ; then echo "error : input.pcap not found" ; exit 1 ; fi
	./$(TARGET) input.pcap output.pcap | tee dscr.log

$(TARGET) : $(SRCS)
	go mod tidy
	go fmt $(SRCS)
	GOOS=linux GOARCH=amd64 go build -o $(TARGET) $(SRCS)
	chmod +x $@

clean:
	rm -f go.sum dscr.log $(TARGET)
