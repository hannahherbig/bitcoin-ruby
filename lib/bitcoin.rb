require 'bindata'
require 'ipaddress'

# Wraps the IPAddress::IPv6 class found in the ipaddress gem to provide easier
# handling of binary-format IP addresses
# @author Nick Thomas <nick@lupine.me.uk>
class Ipv6Address < BinData::Primitive
    endian :big

    uint128 :address

    def get
        if address
            # v6-mapped v4
            if address >= 0xffff00000000 && address <= 0xffffffffffff
                IPAddress::IPv6::Mapped.parse_u128(address)
            else # v6
                IPAddress::IPv6.parse_u128(address)
            end
        else
            nil # Nothing set
        end
    end

    def set(v)
        v = IPAddress::IPv6::Mapped.new(v.to_s) if v.is_a?(IPAddress::IPv4)
        v = IPAddress(v.to_s) unless v.is_a?(IPAddress::IPv6)

        if v.respond_to?(:to_u128)
            address = v.to_u128
        else
            raise ArgumentError, "Can't set #{v.class} to an IPv6Address"
        end
    end
end



# Implementation of the BitCoin wire protocol, written using bindata.
# Reference: https://en.bitcoin.it/wiki/Protocol_specification
#
# @author Nick Thomas <nick@lupine.me.uk>
module Bitcoin

class << self
    def CURRENT_VERSION(network = :main)
        VERSIONS[network]
    end
end

# Comprehensive list of known networks. The hex values are what you see in
# MessageHdr#magic and the symbols are their known friendly names.
NETWORKS = {
    :testnet => 0xDAB5BFFA,
    :main    => 0xD9B4BEF9
}

# The current supported protocol version for the various networks.
VERSIONS = {
    :main => 32100
}

# Comprehensive list of known inventory vector types.
INV_VEC_TYPES = {
    0 => :error,
    1 => :msg_tx,
    2 => :msg_block
}

# Used in Reply messages
REPLY_CODES = {
    0 => :success,
    1 => :wallet_error,
    2 => :denied
}

# Make all of the hash values also point to the keys.
[NETWORKS, VERSIONS, INV_VEC_TYPES, REPLY_CODES].each do |hash|
    hash.update(hash.invert)
end

# Only Alert messages signed by this key are valid.
# This is an ECDSA public key (FIXME: in what format?)
ALERT_PUBKEY = "04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b" +
    "28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284"

## Components of payloads ##

# Bitmask advertising various capabilities of the node.
# @author Nick Thomas <nick@lupine.me.uk>
class ServicesMask < BinData::Record
    endian  :little

    bit7    :top_undefined
    bit1    :node_network
    bit56   :undefined
end

# Structure holding an IP address and port in a slightly unusual format.
# This one is big-endian - everything else is little-endian.
#
# @author Nick Thomas <nick@lupine.me.uk>
class NetAddr < BinData::Record
    endian          :big

    services_mask   :services
    ipv6_address    :ip # IPv4 addresses given as IPv6-mapped IPv4
    uint16          :port
end

# Like a NetAddr but with a timestamp to boot.
# @author Nick Thomas <nick@lupine.me.uk>
class TimestampedNetAddr < BinData::Record
    endian      :little

    uint32      :timestamp # TODO: Allow this to be set with Ruby native types
    net_addr    :net_addr
end

# Variable-length integer. This is slightly scary.
# @author Nick Thomas <nick@lupine.me.uk>
class VarInt < BinData::BasePrimitive
    register_self

    def value_to_binary_string(val)
        val = val.to_i

        if val < -0xffffffffffffffff # unrepresentable
            ""
        elsif val < 0    # 64-bit negative integer
            top_32 = ((-val) & 0xffffffff00000000) >> 32
            btm_32 = (-val) & 0x00000000ffffffff
            [0xff, top_32, btm_32].pack("CVV")
        elsif val <= 0xfc # 8-bit (almost) positive integer
            [val].pack("C")
        elsif val <= 0xffff # 16-bit positive integer
            [0xfd, val].pack("Cv")
        elsif val <= 0xffffffff # 32-bit positive integer
            [0xfe, val].pack("CV")
        else    # We can't represent this, whatever it is
            ""
        end
    end

    def read_and_return_value(io)
        magic = read_uint8(io)
        if magic <= 0xfc # 8-bit (almost) positive integer
            magic
        elsif magic == 0xfd # 16-bit positive integer
            read_uint16(io)
        elsif magic == 0xfe # 32-bit positive integer
            read_uint32(io)
        elsif magic == 0xff # 64-bit negative integer
            -(read_uint64(io))
        end
    end

    def sensible_default
        0
    end

    protected

    def read_uint8(io)
        io.readbytes(1).unpack("C").at(0)
    end

    def read_uint16(io)
        io.readbytes(2).unpack("v").at(0)
    end

    def read_uint32(io)
        io.readbytes(4).unpack("V").at(0)
    end

    def read_uint64(io)
        top, bottom = io.readbytes(8).unpack("VV")
        (top << 32) | bottom
    end
end

# Variable-length pascal string with a variable-length int specifying the
# length. I kid you not.
# @author Nick Thomas <nick@lupine.me.uk>
class VarStr < BinData::Primitive
    endian :little

    var_int :len, :value => lambda { data.length }
    string  :data, :read_length => :len

    def get    ; self.data     ; end
    def set(v) ; self.data = v ; end
end

class InventoryVector < BinData::Record
    endian :little

    uint32 :type # For values, see INV_VEC_TYPES
    string :iv_hash, :length => 32
end

# Simple class wrapping raw SHA256 data. Might have utility methods later.
# @author Nick Thomas <nick@lupine.me.uk>
class Sha256 < BinData::Record
    string :data, :length => 32 # Raw SHA256 data
end
SHA256 = Sha256

# @author Nick Thomas <nick@lupine.me.uk>
class TransactionIn < BinData::Record
    endian :little

    sha256 :po_hash
    uint32 :po_index

    var_str :signature_script
    uint32  :sequence # Version of this record.
end

# @author Nick Thomas <nick@lupine.me.uk>
class TransactionOut < BinData::Record
    endian  :little

    uint64  :txout_value
    var_str :pk_script # Script containing conditions to claim to transaction
end

# Header for a block.
# @author Nick Thomas <nick@lupine.me.uk>
class BlockHdr < BinData::Record
    endian  :little

    uint32  :version
    sha256  :prev_block
    sha256  :merkle_root
    uint32  :timestamp
    uint32  :difficulty
    uint32  :nonce
    var_int :txn_count
end

## Payloads ##

# Payload for a version message
# @author Nick Thomas <nick@lupine.me.uk>
class Version < BinData::Record
    endian :little

    uint32          :version
    services_mask   :services
    uint64          :timestamp
    net_addr        :addr_me
    net_addr        :addr_you,     :onlyif => lambda { version >= 106 }
    uint64          :nonce,        :onlyif => lambda { version >= 106 }
    var_str         :sub_version,  :onlyif => lambda { version >= 106 }
    uint32          :start_height, :onlyif => lambda { version >= 209 }
end

# Payload for an addr message in versions earlier than 31402. These are
# used to get a list of peers to interact with.
# @author Nick Thomas <nick@lupine.me.uk>
class AddrPre31402 < BinData::Record
    endian :little

    var_int :addr_count
    array :addrs, :type => :net_addr,
        :read_until => lambda { index == addr_count - 1 }

end

# Payload for an addr message in versions later than 31402. A timestamp was
# added to the list of addresses, but otherwise it's the same as AddrPre31402
# @author Nick Thomas <nick@lupine.me.uk>
class AddrFrom31402 < BinData::Record
    endian :little

    var_int :addr_count
    array :timestamped_addrs, :type => :timestamped_net_addr,
                            :read_until => lambda { index == addr_count - 1 }
end

# Payload for a getdata or inv message. This lets the peer advertise the
# various objects it has knowledge of.
# @author Nick Thomas <nick@lupine.me.uk>
class Inventory < BinData::Record
    endian  :little

    var_int :iv_count
    array :items, :type => :inventory_vector,
                            :read_until => lambda { index == iv_count - 1 }
end

# Payload for a getblocks or getheaders message. Specifies a set of blocks
# that the sender wants details of.
# @author Nick thomas <nick@lupine.me.uk>
class BlockSpec < BinData::Record
    endian  :little

    uint32  :version
    var_int :start_count
    array   :hash_start, :type => :sha256,
                            :read_until => lambda { index == start_count - 1 }
    # Hash of the last desired block, or 0 to get as many as possible
    # (max: 500)
    sha256  :hash_stop, :length => 32
end

# A transaction. This contains a number of transactions 'in', and 'out'.
# @author Nick Thomas <nick@lupine.me.uk>
class Transaction < BinData::Record
    endian  :little

    uint32  :version
    var_int :tx_in_count
    array   :transactions_in, :type => :transaction_in,
                            :read_until => lambda { index == tx_in_count - 1 }
    var_int :tx_out_count
    array   :transactions_out, :type => :transaction_out,
                        :read_until => lambda { index == tx_out_count - 1 }
    uint32  :lock_time
end

# Details about a particular block. Returned in response to a block request
# @author Nick Thomas <nick@lupine.me.uk>
class Block < BinData::Record
    endian      :little

    block_hdr   :header
    array       :txns, :type => :transaction,
                    :read_until => lambda { index == header.txn_count - 1 }
end

# Headers payloads are returned in response to a getheaders request.
# Limit of 2,000 entries per message.
# @author Nick Thomas <nick@lupine.me.uk>
class Headers < BinData::Record
    endian  :little

    var_int :hdr_count
    array   :block_hdrs, :type => :block_hdr,
                            :read_until => lambda { index == hdr_count - 1 }

end

# For now, we don't support CheckOrder requests at all. Protocol documentation
# is lacking! FIXME
# @author Nick Thomas <nick@lupine.me.uk>
class CheckOrder < BinData::Record
    endian :little
end

# We don't support SubmitOrder replies either. Receiving either of these will
# actually break the stream, since we don't even know how long they are. FIXME
# @author Nick Thomas <nick@lupine.me.uk>
class SubmitOrder < BinData::Record
    endian :little
end

# Used as a response to a CheckOrder request.
# @author Nick Thomas <nick@lupine.me.uk>
class Reply < BinData::Record
    endian :little

    uint32 :reply # See REPLYCODES for possible values
end

# Completely empty payload. BinData dies if we don't specify *something*
# in the message payload choices.
# @author Nick Thomas <nick@lupine.me.uk>
class NullPayload < BinData::Record
    endian :little
end

# A message sent using the p2p network. Signed by a key so you can tell who
# sent it - if it's signed by a particular key, then we should apparently
# show the message to the user and cease operation until further notice. Fun!
# @author Nick Thomas <nick@lupine.me.uk>
class Alert < BinData::Record
    endian  :little

    var_str :message
    var_str :signature
end

## Top-level message format ##

# Found at the start of all Bitcoin messages.
# @author Nick Thomas <nick@lupine.me.uk>
class MessageHdr < BinData::Record
    endian :little
    uint32 :magic
    string :command, :length => 12
    uint32 :payload_len
    uint32 :checksum, :onlyif => :has_checksum?

    protected

    # version and verack messages don't have a checksum. The rest do.
    # @return[Boolean] does this message header have a checksum field or not?
    def has_checksum?
        !%w|version verack|.include?(command.strip)
    end
end


# Everything on the wire is a Message.
# @author Nick Thomas <nick@lupine.me.uk>
class Message < BinData::Record

    # @param[Fixnum,nil] version The protocol version. Setting this affects
    # the layout of various fields.
    def initialize_instance(v = nil)
        super()
        @version = v || ::Bitcoin::CURRENT_VERSION(:main)
    end

    message_hdr :header

    choice :payload, :selection => :payload_choice do
        version         "version"
        addr_pre31402   "addr_pre31402"
        addr_from31402  "addr_from31402"
        inventory       "inv"
        inventory       "getdata"
        block_spec      "getblocks"
        block_spec      "getheaders"
        transaction     "tx"
        block           "block"
        headers         "headers"
        check_order     "checkorder"
        submit_order    "submitorder"
        alert           "alert"
        null_payload    "null"
    end

    # Works out what the payload looks like based on the MessageHdr struct
    # and (potentially) the version
    def payload_choice
        cmd = header.command.to_s.strip
        return cmd if %w{version inv getdata getblocks getheaders tx block
            headers alert}.include?(cmd)

        # We can't parse these yet, and so we don't know where in the stream
        # the next message starts. So all we can do is throw an error
        raise NotImplementedError, "Received unsupported command #{cmd}" if
            %w|checkorder submitorder|.include?(cmd)

        # These commands don't have any payloads
        return "null" if %w|verack getaddr ping|.include?(cmd) || cmd == ""

        # Payload has two forms, depending on protocol version. Ugh.
        return (@version < 31402 ? "addr_pre31402" : "addr_from31402") if
            cmd == "addr"

        raise NotImplementedError, "Unknown command: #{cmd}"
    end

end

end # module Bitcoin
