# starline_e96_re
Reverse engineering of the starline hid USB debug protocol.

Starline e96 is a peace of junk car alarm system with tons of bugs. 
Due to some hw limitation this car alarm have very small working radius for communication with RC.

Fortunately, this device have USB debug port for configuration purposes.
This port uses USB hid protocol for communication. So, no proprietary driver required.

With the help of the NSA's tool Ghidra I have reversed quite big part of the starline debug protocol.
Then I have put raspberry pi zero W with 4G modem into my car and write simple Linux demon to replace RC with the telegram messenger and mobile phone. 

This QT project demonstrates how to control some of the car alarm features such as engine start/stop, arm/disarm through the my telegram bot API library.

Futher instructions will be added soon.
  
