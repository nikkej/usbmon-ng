# usbmon-ng
Next generation USB traffic monitoring application which utilizes threads and libudev for device presence detection at application start up, and device attach & detach events as well.

Done: mmap'ed ioctl abandoned, now pcap library reads pseudo file handle and dumps pcap data to file.

ToDo: More error checking & handling...
