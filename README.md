# schc-json-parser
SCHC Library to parse an unparse LoRaWAN SCHC Packets into and from a JSON Format

# To install the library

pip3 install git+https://github.com/openschc/schc-json-parser.git


# An example to compress IPv6/UDP Packets into bytearray and JSON Format

```Compression_101.py```

# An example to parse IPv6/ICMP SCHC Fragments into JSON

```icmp_example.py```

# An example to parse IPv6/UDP SCHC Fragments into JSON

```Parser_example.py```

# IPv6/UDP compression lorawan Rules:

```lorawan.json``` ---> 101, 100 (Compression), 20 (Frag UP), 21 (Frag DW)

# ICMP Rules:

```icmp2.json``` ---> Compression and NoAck

```icmp3.json``` ---> Compression and AckOnError
