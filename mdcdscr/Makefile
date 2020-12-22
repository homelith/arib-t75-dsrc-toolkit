################################################################################
# Makefile for go project
################################################################################
MERGE_TGT := ofsmerge
MERGE_SRC := ofsmerge.go
DSCR_TGT  := mdcdscr
DSCR_SRC  := mdcdscr.go
GOPKGS    := \
	github.com/google/gopacket \
	github.com/google/gopacket/layers \
	github.com/google/gopacket/pcapgo \
	golang.org/x/net/bpf

# if no GOPATH set, use "~/go" as default
ifeq ($(GOPATH),)
GOPATH := ~/go
endif

default : merge

################################################################################
# go get rule generator
define GOGET_FOREACH
PREFIXED_GOPKGS := $(PREFIXED_GOPKGS) $(GOPATH)/src/$(1)
$(GOPATH)/src/$(1) :
	go get -u $(1)
endef
$(foreach P, $(GOPKGS), $(eval $(call GOGET_FOREACH,$(P))))
################################################################################

merge : $(MERGE_TGT)
	./$(MERGE_TGT) -o 0 downlink.pcap uplink.pcap merge.pcap

dscr : $(DSCR_TGT)
	./$(DSCR_TGT) merge.pcap dscr.pcap | tee dscr.log

$(MERGE_TGT) : $(MERGE_SRC) $(PREFIXED_GOPKGS)
	go fmt $(firstword $^)
	go build $(firstword $^)
	chmod +x $@

$(DSCR_TGT) : $(DSCR_SRC) $(PREFIXED_GOPKGS)
	go fmt $(firstword $^)
	go build $(firstword $^)
	chmod +x $@

clean:
	rm -f $(MERGE_TGT) $(DSCR_TGT)
