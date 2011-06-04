require 'spec_helper'
require 'btc_wire_proto'

# Fixtures data. Taken from: https://en.bitcoin.it/wiki/Protocol_specification

include ::BtcWireProto

describe ::BtcWireProto do

  # Payload fragments
  describe ServicesMask do
    it "should have node_network set to false when its bit is 0" do
      s = ServicesMask::read("\x00" * 8) # All 64 bits unset
      s.node_network.should == 0
      
      s = ServicesMask::read(binary(%w{01 00 00 00 00 00 00 00}))
      s.node_network.should == 1
    end
  end

  describe NetAddr do
    it "should have all fields set to 0 when the input data is all zeroes" do
      na = NetAddr::read("\x00" * 26)
    
      na.services.node_network.should == 0
      na.ip.to_u128.should == 0
      na.port.should == 0
    end
    
    it "Should allow the Ip field to be set with Ruby native types" do
      na = NetAddr::read("\x00" * 26)
      mip = IPAddress("::ffff:0.0.0.1")
      na.ip = mip
      na.ip.to_u128.should == mip.to_u128
    end
    
    it "should have the fields set appropriately when fed binary data" do  
      na = NetAddr::read(
        binary(%w{
          01 00 00 00 00 00 00 00 00 00 00 00 00
          00 00 00 00 00 FF FF 0A 00 00 01 20 8D
        })
      ) 

      na.services.node_network.should == 1
      na.ip.to_s.should == "::ffff:10.0.0.1"
      na.port.should == 8333
    end
  end


  describe TimestampedNetAddr do
    it "should leverage NetAddr" do
      tna = TimestampedNetAddr::read("\x00" * 30)
      tna.net_addr.class.should == BtcWireProto::NetAddr
    end

    it "should have all fields set to 0 when the input data is all zeroes" do
      tna = TimestampedNetAddr::read("\x00" * 30)
      tna.timestamp.should == 0
    end
     
    it "should have the fields set appropriately when fed binary data" do  
      tna = TimestampedNetAddr::read(
        binary(%w{
          E2 15 10 4D 01 00 00 00 00 00 00 00 00 00 00
          00 00 00 00 00 00 00 FF FF 0A 00 00 01 20 8D
         })
      ) 
      
      tna.timestamp.should == 1292899810

      tna.net_addr.services.node_network.should == 1
      tna.net_addr.ip.to_s.should == "::ffff:10.0.0.1"
      tna.net_addr.port.should == 8333
    end
  end


  describe VarInt do
    it "should hold numbers <  0x00000000 in nine bytes" do
      bin_minus_1 = "\xff" + "\x00\x00\x00\x00" + "\x01\x00\x00\x00"
      a = VarInt::read(bin_minus_1)
      a.should == -1
      a.num_bytes.should == 9
      a.to_binary_s.should == bin_minus_1
            
      a = VarInt::read("\xff" * 9)
      a.should == -(2**64 - 1)
      a.num_bytes.should == 9
      a.to_binary_s.should == "\xff" * 9
    end

    it "should hold numbers >= 0x00000000 and < 0x000000fd in one byte" do
      a = VarInt::read("\x00")
      a.should == 0x00
      a.num_bytes.should == 1
      a.to_binary_s.should == "\x00"

      a = VarInt::read("\xFC")
      a.should == 0xFC
      a.num_bytes.should == 1
      a.to_binary_s.should == "\xFC"
    end
    
    it "should hold numbers >= 0x000000fd and < 0x00010000 in three bytes" do
      a = VarInt::read("\xFD\xFD\x00")
      a.should == 0xFD
      a.num_bytes.should == 3
      a.to_binary_s.should == "\xFD\xFD\x00"
      
      a = VarInt::read("\xFD\xFF\xFF")
      a.should == 0xFFFF
      a.num_bytes.should == 3
      a.to_binary_s.should == "\xFD\xFF\xFF"
    end

    it "should hold numbers >= 0x00010000 and < 0xffffffff in five bytes" do
      a = VarInt::read("\xFE\x00\x00\x01\x00")
      a.should == 0x10000
      a.num_bytes.should == 5
      a.to_binary_s.should == "\xFE\x00\x00\x01\x00"
      
      a = VarInt::read("\xFE\xFF\xFF\xFF\xFF")
      a.should == 0xFFFFFFFF
      a.num_bytes.should == 5
      a.to_binary_s.should == "\xFE\xFF\xFF\xFF\xFF"

    end
  end

  describe VarStr do
    it "should store string length in a var_int" do
      a = VarStr::read("\x04abcd")
      a.should == "abcd"
      a.num_bytes.should == 5
      a.to_binary_s.should == "\x04abcd"
      
      a = VarStr::read("\xFD\xFF\xFF" + "A" * 0xFFFF)
      a.should == "A" * 0xFFFF
      a.num_bytes.should == 0xFFFF + 3
      a.to_binary_s.should == "\xFD\xFF\xFF" + "A" * 0xFFFF
    end
  end

  describe InventoryVector do
  end

  describe Sha256 do
  end

  describe TransactionIn do
  end

  describe TransactionOut do
  end

  describe BlockHdr do
  end
  
  # Payloads
  
  describe Version do
    it "should interpret binary data correctly" do
      ver = Version::read(binary(%w{
        9C 7C 00 00 01 00 00 00 00 00 00 00 E6 15 10 4D 00 00 00 00
        01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF
        0A 00 00 01 DA F6 01 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 FF FF 0A 00 00 02 20 8D DD 9D 20 2C 3A B4 57 13
        00 55 81 01 00
      }))

      ver.version.should == 31900
      ver.services.node_network.should == 1
      ver.timestamp.should == 1292899814
      ver.addr_me.class.should == NetAddr
      ver.addr_you.class.should == NetAddr
      ver.nonce.should == 0x1357B43A2C209DDD
      ver.sub_version.should == ""
      ver.start_height.should == 98645
    end
    
    it "should exclude some fields by version" do
      v = Version::read([1].pack("V") + "\x00" * 42)
      v.num_bytes.should == 46
      v = Version::read([106].pack("V") + "\x00" * 77)
      v.num_bytes.should == 81
      v = Version::read([209].pack("V") + "\x00" * 81)
      v.num_bytes.should == 85
    end
  end
  
  describe AddrPre31402 do
  end
  
  describe AddrFrom31402 do
  end
  
  describe Inventory do
  end
  
  describe BlockSpec do
  end
  
  describe Transaction do
  end
  
  describe Block do
  end
  
  describe Headers do
  end
  
  describe CheckOrder do
  end
  
  describe SubmitOrder do
  end
  
  describe Reply do
  end
  
  describe Alert do
  end
  

  # Messages
  describe MessageHdr do
  end
  
  describe Message do
    context "Version message" do
      it "should have a Version payload" do
        m = Message::new(:header => {:command => 'version'})
        m.payload.selection.should == "version"
      end
      
      it "should parse binary data correctly" do
        m = Message::read(binary(%w{
          F9 BE B4 D9 76 65 72 73 69 6F 6E 00 00 00 00 00 55 00 00
          00 9C 7C 00 00 01 00 00 00 00 00 00 00 E6 15 10 4D 00 00
          00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
          00 FF FF 0A 00 00 01 DA F6 01 00 00 00 00 00 00 00 00 00
          00 00 00 00 00 00 00 00 FF FF 0A 00 00 02 20 8D DD 9D 20
          2C 3A B4 57 13 00 55 81 01 00
        }))
        m.header.magic.should == BtcWireProto::NETWORKS[:main]
        m.header.command.should == "version\x00\x00\x00\x00\x00"
        m.header.payload_len.should == 85
        m.header.has_parameter?(:checksum).should be_false
        m.payload.version.should == 31900
        m.payload.services.node_network.should == 1
        m.payload.timestamp.should == 1292899814
        m.payload.addr_me.class.should == NetAddr
        m.payload.addr_you.class.should == NetAddr
        m.payload.nonce.should == 0x1357B43A2C209DDD
        m.payload.sub_version.should == ""
        m.payload.start_height.should == 98645
        
      end
    end
    
    context "Verack message" do
      it "should have no payload" do
        m = Message.new(:header => {:command => "verack"})
        m.payload.selection.should == "null"
      end

      it "should parse the binary data correctly" do
        m = Message::read(binary(%w{
          F9 BE B4 D9 76 65 72 61 63 6B 00 00 00 00 00 00 00 00 00 00
        }))
        m.header.magic.should == BtcWireProto::NETWORKS[:main]
        m.header.command.should == "verack\x00\x00\x00\x00\x00\x00"
        m.header.payload_len.should == 0
        m.header.has_parameter?(:chcksum).should be_false
      end

    end
  end
  
end
