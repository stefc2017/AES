COMP 4140
Assignment 3, README.md
Stefan Couture, 7771638
userId: coutures

How to my compile my AES Application (aesStefanCouture.c)?
- Run the command in commandline: make
- My application is written in C

How to run my AES Application (aesStefanCouture)
- Run the command ./aesStefanCouture testPlaintext.txt testKey.txt aes_sbox.txt aes_inv_sbox.txt (format ./aesStefanCouture plaintext key sbox inverseSbox) where each argument is a file
- The plaintext.txt, key.txt, sbox.txt and inversesbox.txt all follow the formats of the
  sample files in the COMP 4140 Assignment 3 instructions. The data like in the COMP 4140 Assignment 3 instructions are all hex.
  As well like in the sample input files, there must be at least 1 space between two hex characters such as: ab bc 02

I have also included an output file named outputA3StefanCouture7771638.md that just shows the output you get once you run the C program. My output uses the s-box and inverse s-box that was provided on the course website: http://www.cs.umanitoba.ca/~comp4140/Assignments/aes_sbox.txt and http://www.cs.umanitoba.ca/~comp4140/Assignments/aes_inv_sbox.txt.

My application is written in C named aesStefanCouture.c and contains a header file named aesStefanCouture.h.

