import getopt, sys
import dpkt, pcap
import socket
import struct
import binascii
import textwrap

def main():
    # Get host
    host = socket.gethostbyname(socket.gethostname())
    print('IP: {}'.format(host))

    name = None            
    pc = pcap.pcap(name)
    decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
               pcap.DLT_NULL:dpkt.loopback.Loopback,
               pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()]
    try:
        print 'listening on %s: %s' % (pc.name, pc.filter)
        for ts, pkt in pc:
            pkt = str(decode(pkt))
            dest_mac, src_mac, eth_proto, data = ethernet_frame(pkt)

            print '\nEthernet Frame:'
            print "Destination MAC: {}".format(dest_mac)
            print "Source: {}".format(src_mac)
            print "Protocol: {}".format(eth_proto)
    except KeyboardInterrupt:
        nrecv, ndrop, nifdrop = pc.stats()
        print '\n%d packets received by filter' % nrecv
        print '%d packets dropped by kernel' % ndrop

# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6s2s', data[:14])
    return binascii.hexlify(dest_mac), binascii.hexlify(src_mac), binascii.hexlify(proto), data[14:]

if __name__ == '__main__':
    main()