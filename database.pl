% Reject packet under following conditions

reject("ether", "arp", "2").
reject("tcp", "dst", "port", "12", "src", "port", "1").
reject("udp", "dst", "port", "12", "src", "port", "1").

reject("adapter", "A").
reject("adapter", "B").
reject("adapter", "C").

reject("ipv6", "src", "FF01:0:0:0:0:0:0:101").
reject("ipv6", "dst", "FF01:0:0:0:0:0:0:101").

reject("ip", "src", "172.168.1.1").
reject("ip", "dst", "172.168.1.1").

reject("icmp", "type", "155").
reject("icmp", "code", "155").

reject("icmpv6", "type", "155").
reject("icmpv6", "code", "155").

/* Packet Drop Conditions */

drop("adapter", "D").
drop("adapter", "E").

drop("tcp", "dst", "port", "100", "src", "port", "5").
drop("udp", "dst", "port", "18", "src", "port", "88").

drop("ip", "src", "172.168.1.1").
drop("ip", "dst", "172.168.1.1").