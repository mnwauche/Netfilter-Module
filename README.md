# final-project-coding-taus
Final Project by Joshua Stafford and Michael Nwauche
=================================
BUILDING
=================================

-Open the terminal and change directories to the project root folder ("final-project-coding-taus")

-Build the project by executing the following command:

	>$ make
	
RUNNING
=================================

-The following command will load the module:

	>$ sudo insmod Netfilter.ko
	
-The OS will ask for your password after this. Once you type it in, the module will begin running.

-The following command will terminate the module:

	>$ sudo rmmod Netfilter
	
Commands
--------

	>$ "cat /proc/netfilter_proc"
	
		-Prints the proc file to the terminal

-The following commands can take multiple parameters and require at least one parameter.

	>$ echo "bip <IP-address> <IP-address>..."
		
		-Blocks all traffic coming from and going to the given IP-address
		
		-WARNING: Before you pass an IP address to this command, make sure that the IP address is
		not already being blocked. Passing the same IP address twice will result in undefined
		behavior.
		
	>$ echo "ubip <IP-address> <IP-address>..."
	
		-Ceases to block all traffic coming from and going to the given IP addresses.
		
		-If the IP addresses listed are not currently being blocked, no action is taken.
		
-The following commands require a space between the last letter and the end quotation
		
	>& echo "bait " 			
	
		-Blocks all incoming traffic indiscriminately.
		
	>$ echo "baot "
	
		-Blocks all outgoing traffic indiscriminately.
		
	>$ echo "ubait "
	
		-Stops blocking all incoming traffic (except in the the case of specific IP addresses).
		
	>$ echo "ubaot "
	
		-Stops blocking all outgoing traffic (except in the case of specific IP addresses).
		

TESTING
=================================

-Load and run the module


INDISCRIMINATE HOOK FUNCTION
----------------------------

-Run the following command to block all incoming traffic

	>$ echo "bait "
	
-The following command will attempt to communicate with an IP address

	>$ ping <any IP address or URL>
	
-If the module is running correctly, the terminal should respond with...

-Run the following commands to unblock all incoming traffic

	>$ echo "ubait "
	
	>$ ping <any IP address or URL>
	
-If the module is running correctly, the terminal should begin responding with periodic
"ping" output messages

-To stop pinging, press (modifier key) + C on your keyboard

-Run the following commands to black all outgoing traffic

	>$ echo "baot "
	
	>$ ping <any IP address or URL>
	
-If the module is running correctly, the terminal should tell you that you are unable to 
send messages

-Run the following commands to unblock all outgoing traffic

	>$ echo "ubaot "
	
	>$ ping <any IP address or URL>
	
-If the module is running correctly, the terminal should begin responding with periodic
"ping" output messages

-To stop pinging, press (modifier key) + C on your keyboard


IP HOOK FUNCTION
--------------------

-To block an IP address, run the following command

	>$ echo "bip <IP-address> <IP-address>..."
		
-Try pinging one of the addresses you passed with the following command

	>$ ping <IP address>
	
-You should notice a lack of pinging

-Press (modifier key) + C on your keyboard to stop the ping attempt

-Your terminal should respond with a message that tells you how many communications were
attempted and how many were successful (the number should be 0)

-To unblock a previously blocked IP address, pass the following command
		
	>$ echo "ubip <IP-address> <IP-address>..."
	
-Try pinging one of the addresses you passed with the following command

	>$ ping <IP address>
	
-Your terminal should begin to ping normally

-Press (modifier key) + C on your keyboard to stop pinging

-To print the proc-file to the terminal, pass the following command
	
	->$ "cat <proc-file path>"
	
-Your terminal should respond with a list of previously blocked IP addresses along with the number
of times communication with the address was blocked
