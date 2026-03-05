# pscan
Pscan is a Network Scanner That detects packets and can log them to a pcap file and is made with a Network Filter
# Prerequisites
  * A Linux Device
  * Kernel Version >= 4.13
  * Kernel Headers
  * C Compiler (e,g) gcc , clang
  * Make
# Installation
  Clone the repository
  ~~~
    git clone https://github.com/yoyo95104/pscan.git 
    cd pscan
  ~~~
  Then make the Program
  ~~~
  make
  ~~~  
  Or Install it system-wide with
  ~~~
  sudo make install
  ~~~
  You can uninstall at any time with
  ~~~
  sudo make uninstall
  ~~~
# Usage
 You can log files to .pcap and .pcapng and txt with
 ~~~
 pscan -f log.yourext
 ~~~
 You can also Set a Packet count with
 ~~~
 pscan --count 10
 ~~~
 You can also use the Netfilter , but disclamer it will block  the actual ip/port/protocol from your device , so you may be  logged out of the internet
 ~~~
 pscan --filter "targetport=10,ip=0.0.0.0,dip=0.0.0.0,proto=0 startrange=50,endrange=55"
 ~~~
 dip = Destination ip
 proto = Protocol
 startrange = Start of range to block ports
 endrange = End of range to block ports
# Notice
  You have to run this program with sudo or as root
  # Debugging 
  If the kernel module refused to unload , unload it like this
  ~~~
   sudo rmmod filter
  ~~~
  or Restart
