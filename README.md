# Detect-Dos-Attack
This is code that includes a DOS attack on a specified IP address which only sends packets to that IP address. 
The code also includes a DOS detection, which detects the attack and specifies which IP address the attack is being issued from.

# Instructions-how-to-run-the-programs:
Attacker program: Launch the ‘DosAttack.py’ program using python(from terminal or any other IDE however make sure to have the package of scapy fully installed) like any other program and then the program would first require the user to enter the target IP address he can also choose 1 of 2 speeds in which he specifies the interval between each packet 

Detection Program: Similar to the Attack program, launch the ‘DosDetection.py’ file and the program should automatically run, and once it detects an attack it will immediately show with a print statement on the screen.
