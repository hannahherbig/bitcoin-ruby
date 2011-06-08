# this is just an example. it doesn't totally work yet.

$: << 'lib'

require 'socket'
require 'bitcoin'
require 'open-uri'

def curl(url)
    open(url) { |f| f.read }
end

def log(line)
    timestamp = Time.now.strftime("%H:%M:%S.%L")
    puts "[#{timestamp}] #{line}"
end

sock = TCPSocket.new("irc.andrew12.net", 8333)

# "When a node creates an outgoing connection, it will immediately advertise
# its version. The remote node will respond with its version. No futher
# communication is possible until both peers have exchanged their version."
mess = Bitcoin::Message.new
mess.command = "version"
mess.payload = Bitcoin::Version.new
mess.payload.version = 32200
mess.payload.timestamp = Time.now.to_i
mess.payload.addr_me = {:ip => curl("http://automation.whatismyip.com/n09230945.asp")}
mess.payload.addr_you = {:ip => Socket.gethostbyname("irc.andrew12.net")[3].each_byte.to_a.join('.')}
mess.payload.nonce = rand(2**64)
mess.payload.sub_version = ''
mess.payload.start_height = 0

log "-> #{mess.inspect}"

mess.write(sock)

loop do
    obj = Bitcoin.read(sock)
    log "<- #{obj.inspect}"
    if obj.command == "inv"
        items = obj.payload.items.select { |i| i.type == 1 } # transactions only
        next if items.empty? # no transactions, nothing to do
        mess = Bitcoin::Message.new
        mess.command = "getdata"
        mess.payload = Bitcoin::Inventory.new(:items => items)

        log "-> #{mess.inspect}"

        mess.write(sock)
    end
end
