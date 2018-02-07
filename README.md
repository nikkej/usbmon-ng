# usbmon-ng
Next generation and yet another USB traffic monitoring application which utilizes threads and libudev for device presence detection at application start up, and device attach & detach events as well. PCap library is used to read USB URBs and to store those into file for further processing. Conceptual state chart about thread interactions & life cycles depicted below

..figure :: doc/usbmon-ng-threads.jpeg

