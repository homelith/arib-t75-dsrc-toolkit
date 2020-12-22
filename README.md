# arib-t75-dsrc-toolkit

Toolkit for capturing & decoding 5.8GHz DSRC (Dedicated Short-Range Communications) used on ETC (Electronic Toll Collection) system in Japan

## licenses

- licensed under MIT license from each different contributor, see header of indivisual files.

## files

- /gnuradio : GNU Radio Compagnion (.grc) designs for capturing DSRC signals using HackRF One SDR
  + reconly\_20m.grc : 20Msps capturing with packet detection on +5M/-5M shifted center frequency
  + etc2pcap\_20m\_dual.grc : ARIB STD-T75 ASK signal dual channel demodulator for 20Msps capture
  + etc2pcap\_10m\_single.grc : ARIB STD-T75 ASK signal single channel demodulator for 10Msps capture
  + tested on GNU Radio Compagnion 3.7.13.4 for Windows

- /mdcdscr : golang based tools for manipulating DSRC pcaps
  + ofsmerge.go : downlink and uplink pcaps merger with specified time offset
  + mdcdscr.go : descramble MDC frames by using FCMC LID

## see also

- packet dissector plugin for Wireshark
  + https://github.com/chibiegg/arib-t75-dsrc-wireshark

- interpretive articles (in Japanese)
  + https://qiita.com/homelith/items/9acc6e307f33e73d676c
