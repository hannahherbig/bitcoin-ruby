README
======

bitcoin-ruby is a library that serializes and deserializes messages in the
Bitcoin wire format. Getting the data from (and sending it to) the network,
finding peers, validating blocks, building a block chain, etc. are all out of
scope.

Specification of the protocol is here:
https://en.bitcoin.it/wiki/Protocol_specification

Alternative Ruby libraries that sort-of look at the same area:
[bitcoin-protocol by altamic](https://github.com/altamic/bitcoin-protocol) and
[bitcoin-ruby by lian](https://github.com/lian/bitcoin-ruby).

This library differs from the others in that it leverages bindata to do the
heavy lifting. Results in less, easier-to-read, more robust code.

