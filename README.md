# schc-json-parser
SCHC Library to parse an unparse LoRaWAN SCHC Packets into and from a JSON Format

# To install the library

pip3 install git+https://github.com/openschc/schc-json-parser.git


# An example to compress IPv6/UDP Packets into bytearray and JSON Format

```example.py```

# An example to parse ICMP SCHC Fragments into JSON

```icmp_example.py```

# IPv6/UDP compression lorawan Rules:

```lorawan.json``` ---> 101 and 100

# ICMP Rules:

```icmp2.json``` ---> Compression and NoAck

```icmp3.json``` ---> Compression and AckOnError
