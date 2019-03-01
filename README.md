# Firewall-Prolog

This is an implementation of Firewall rules using Logic Programming(Prolog). 

ENCODING FIREWALL RULES IN PROLOG.
******************************************************
Submitted by:

- Hariharan Srikrishnan (2017A7PS0134P)
- Praveen Ravirathinam (2017A7PS1174P)
- Anirudh Chakravarthy (2017A7PS1195P)

******************************************************

Enter SWI-Prolog by typing swipl in the command line of linux. This will take you the SWI-Prolog interface.

To load the engine, do:

`?- [engine].`


## INPUT

Input for the firewall is done through the engine. There are 3 different ways to input data through the engine here. 


The first way can handle both ethernet protocol and ethernet vid input. Below is its implementation: 

```?- request(Adapter,EthernetProtocolID ,EthernetVID ,IPType ,SrcAddress ,DstAddress ,PortType ,SrcPort ,DstPort ,ICMPType ,ICMPProtocol ,ICMPMessage).```

At a time, only one of the following can be null: 
	
    1. SrcAddress or DstAddress
	2. SrcPort or DstPort
	3. ICMPProtocol or ICMPMessage.



The second way handles only ethernet protocol input and not ethernet vid. Below is its implementation:

```?- request(Adapter,EthernetProtocolID ,IPType ,SrcAddress ,DstAddress ,PortType ,SrcPort ,DstPort ,ICMPType ,ICMPProtocol ,ICMPMessage).```

At a time, only one of the following can be null: 
	
    1. SrcAddress or DstAddress
	2. SrcPort or DstPort
	3. ICMPProtocol or ICMPMessage.



The third way handles only ethernet vid input and not ethernet protocol. Below is its implementation:

```?- request(Adapter,EthernetVID ,IPType ,SrcAddress ,DstAddress ,PortType ,SrcPort ,DstPort ,ICMPType ,ICMPProtocol ,ICMPMessage).```

At a time, only one of the following can be null: 
	
    1. SrcAddress or DstAddress
	2. SrcPort or DstPort
	3. ICMPProtocol or ICMPMessage.



The common key for all 3 methods is given by:

- Adapter is the adapter input. Possible inputs for Adapter are: "A", "B", "C", "D", "E", "F", "G", "H", "any".
- EthernetProtocolID is the ethernet protocol input. Possible inputs for EthernetProtocolID are: "arp", "aarp", "atalk", "ipx", "mpls", "netbui", "pppoe", "rarp", "sna", "xns".
- EthernetVID is the ethernet vid input, eg."1". It is an integer in the range 0-255. It can take multiple inputs at once that are separated by a comma. For example, "1,4,5".
- IPType is the type of internet protocol being input, i.e, either ipv4 or ipv6. if one wants to use ipv4 one must type "ip" in the place of IPType and if one wants to use ipv6 one must type "ipv6" in the place of IPType.
- SrcAddress is the source address of the packet, eg."172.2.2.2"
- DstAddress is the destination address of the packet, eg."172.2.2.4"
- PortType is used to specify whether the input uses TCP or UDP. If one wants to use TCP one must type "tcp" in the place of PortType and if one wants to use UDP one must type "udp" in the place of PortType.
- SrcPort is the source port of the TCP/UDP entered, eg."12345". It is an integer in the range 0-65535.
- DstPort is the destination port of the TCP/UDP entered. eg."17452". It is an integer in the range 0-65535.
- ICMPType is the version of ICMP one wants to use. If one wants to use IMCP one must type "icmp" in the place of ICMPType and if one wants to use ICMPv6 one must type "icmpv6" in place of ICMPType.
- ICMPProtocol is the protocol part of the ICMP input eg."172". It is an integer in the range 0-255.
- ICMPMessage is the message-code part of the ICMP input eg."172". It is an integer in the range 0-255.


Here are a few sample inputs:

```?- request("any","arp","123","ip","172.123.12.1","172.123.12.2","tcp","1223","1224","icmp","123","122").    //method 1```

```?- request("A","atalk","ipv6","172.123.12.1","172.123.12.2","tcp","1223","1224","icmpv6","123","122").	     //method 2```

```?- request("B","145","ipv6","172.123.12.4","172.123.12.2","tcp","1283","1284","icmpv6","153","152").          //method 3```



## DATABASE 

The database.pl file stores cases for which the packets are to be rejected & dropped.

### Rejecting packets:

If one wants to reject a packet one must enter the packet to be rejected in the database file in the format specified below:

- If one wants to reject an adapter X in the database file one must write-- reject("adapter","X"), where X is the adapter.
- If one wants to reject a source ipv4 X in the database file one must write -- reject("ip", "src", "X"), where X is the source IP.
- If one wants to reject a destination ipv4 X in the database file one must write -- reject("ip", "dst", "X"), where X is the destination IP.
- If one wants to reject a source ipv6 X in the database file one must write -- reject("ipv6", "src", "X"), where X is source IP. eg.FF01:0:0:0:0:0:0:101
- If one wants to reject a destination ipv6 X in the database file one must write -- reject("ipv6", "dst", "X"), where X is destination IP. eg.FF01:0:0:0:0:0:0:101
- If one wants to reject a type ICMP X in the database file one must write -- reject("icmp", "type", "X"), where X is type ICMP.
- If one wants to reject a code ICMP X, in the database file one must write -- reject("icmp", "code", "X"), where X is code ICMP.
- If one wants to reject a type ICMPv6 X in the database file one must write -- reject("icmpv6", "type", "X"), where X is type ICMPv6.
- If one wants to reject a code ICMPv6 X in the database file one must write -- reject("icmpv6", "code", "X"), where X is code ICMPv6.
- If one wants to reject a TCP in the database file one must write -- reject("tcp", "dst", "port", "X", "src", "port", "Y"), where X is the destinationport a nd Y is the source port.
- If one wants to reject a UDP in the database file one must write -- reject("udp", "dst", "port", "X", "src", "port", "Y"), where X is the destination port and Y is the source port.


### Dropping packets:


If one wants to drop a packet one must enter the packet to be dropped in the database file in the format specified below:

- If one wants to drop an adapter X in the database file one must write -- drop("adapter", "X"), where X is the adapter.
- If one wants to drop a source ipv4 X in the database file one must write -- drop("ip", "src", "X"), where X is the source IP.
- If one wants to drop a destination ipv4 X in the database file one must write -- drop("ip", "dst", "X"), where X is the destination IP.
- If one wants to drop a source ipv6 X in the database file one must write -- drop("ipv6", "src", "X"), where X is source IP. eg.FF01:0:0:0:0:0:0:101
- If one wants to drop a destination ipv6 X in the database file one must write -- drop("ipv6", "dst", "X"), where X is destination IP.      		eg.FF01:0:0:0:0:0:0:101
- If one wants to drop a type ICMP X in the database file one must write -- drop("icmp", "type", "X"), where X is type ICMP.
- If one wants to drop a code ICMP X in the database file one must write -- drop("icmp", "code", "X"), where X is code ICMP.
- If one wants to drop a type ICMPv6 X in the database file one must write -- drop("icmpv6", "type", "X"), where X is type ICMPv6.
- If one wants to drop a code ICMPv6 X in the database file one must write -- drop("icmpv6", "code", "X"), where X is code ICMPv6.
- If one wants to drop a TCP in the database file one must write -- drop("tcp", "dst", "port", "X", "src", "port", "Y"), where X is the destination port and Y is the source port.
- If one wants to drop a UDP in the database file one must write -- drop("tcp", "dst", "port", "X", "src", "port", "Y"), where X is the destination port and Y is the source port.).

A few instances for rejecting and dropping packets have been mentioned in the "database.pl".


 In the package, a "parser.pl" file is also present, that is used to parse a given firewall language statement into its component parts and then check if it has to be dropped or rejected. This was being developed in an attempt to make the configuration file "database.pl" into a text file "database.txt" that will have support for just having the clauses there as there would be in an actual firewall. It is close to completion but has not been implemented in this program. For instance, if there is a clause in the configuration.txt file, say: 
`ip src addr "172.168.1.1" dst addr "172.168.1.5" proto "255"`
the parser would parse this input and identify that it is a clause to block packets from the source "172.168.1.1" and to the destination "172.168.1.5" through a protocol type 255.

This functionality would have enabled this program to be closer in practice to a deployable firewall.






