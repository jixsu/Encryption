//============================================================================
// Name        : project2.cpp
// Author      : Jackson Xiao
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <cmath>

char *encode(char *plaintext, unsigned long key);

char *encode(char *plaintext, unsigned long key) {
	int s[256];

	for (int k{0}; k <= 255; k++) {
		s[k] = k;
	} // initializes array s[] with s[k] = k from 0 to 255

	int i{0};
	int j{0};
	int k, kthbit, temp, r, R, size;
	unsigned long shift;

	for (int x{0}; x <= 255; x++) {
		k = i%64;

		shift = key >> k; // shifts the kth bit to the 0th bit
		kthbit = shift & 1; // bitwise AND operator with 1 to determine if kthbit is 1 or 0

		j = (j + s[i] + kthbit)%256;
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;
		i = (i + 1)%256;
	}

	if (plaintext[0] == '\0') { // accounts for if the first character was a null character
		size = 0;
	} else {
		for (int x{0}; plaintext[x] != '\0'; x++) {
			size = x;
		}
		size += 1; // determines number of chars in plaintext
	}


	int numgroups{0};
	int additionalsize{0};
	if (size%4 != 0) {
		additionalsize = 4 - size%4;
		numgroups = size/4 + 1;
	} else {
		numgroups = size/4;
	} // if size is not divisible by 4, adds space to make size divisible by four
	// also determines number of groups of 4 there are

	char *plaintextedited = new char[(size + additionalsize)]; // initiated a new plaintext to add excess null characters if necessary
	char *ciphertext = new char[(size + additionalsize)]; //initiates ciphertext array, size of ciphertext is divisble by 4

	for (int x{0}; x <= (size -1); x++) {
		plaintextedited[x] = plaintext[x];
	} // copy pasted plaintext into plaintextedited

	if (additionalsize != 0) {
		for (int x = (size); x <= (size + additionalsize - 1); x++) {
			plaintextedited[x] = '\0';
		}
	} // if the size was not originally divisible by four, null characters are added to make plaintextedited divisible by 4


	for (int x{0}; x <= (size + additionalsize - 1); x++) {
		i = (i + 1)%256;
		j = (j + s[i])%256;
		temp = s[j];
		s[j] = s[i];
		s[i] = temp;
		r = (s[i] + s[j])%256;
		R = s[r];
		ciphertext[x] = plaintextedited[x]^R;
	} // the XOR value between R and plaintext is stored in ciphertext


	unsigned int num1, num2, num3, num4, total;
	char *asciiarmor = new char[((size+additionalsize)*5/4 + 1)]; // initiates new array to hold asciiarmor version of ciphertext

	for (int x{0}; x <= (numgroups-1); x++) {
		for (int y{0}; y <= 3; y++) { // nested for loop that goes through the ciphertext in groups of 4, and converts each group of 4 into ascii armor

			if ((y+1)%4 == 1) { // if it is first of the group of 4, it is bitshifted to the left by 24
				num1 = static_cast<unsigned char>(ciphertext[(y + x*4)]) << 24;
			}
			else if ((y+1)%4 == 2) { // if it is the second of the group of 4, it is bitshifted to the left by 16
				if (ciphertext[(y + x*4)] == '\0') { // if the character is a null character, the number is just 0
					num2 = 0;
				} else {
					num2 = static_cast<unsigned char>(ciphertext[(y + x*4)]) << 16;
				}
			}
			else if ((y+1)%4 == 3) { // if it is the third of the group of 4, it is bitshifted to the left by 8
				if (ciphertext[(y + x*4)] == '\0') {
					num3 = 0;
				} else {
					num3 = static_cast<unsigned char>(ciphertext[(y + x*4)]) << 8;
				}
			}
			else if ((y+1)%4 == 0) {
				if (ciphertext[(y + x*4)] == '\0') {
					num4 = 0;
				} else {
					num4 = static_cast<unsigned char>(ciphertext[(y + x*4)]);
				}
			}

		}
		total = num1 + num2 + num3 + num4; // since the numbers are bitshifted, they can be added up together to form the 32 bit integer representing each group of 4 characters
		for (int z{4}; z >= 0; z--) { // converts it into ascii armor
			asciiarmor[(z) + x*5] = total%85 + 33;
			total = total/85;
		}
	}

	asciiarmor[(size + additionalsize)*5/4] = '\0'; // adds a null character to the end of the ascii armor array

	return asciiarmor; // returns address of ascii armor
}

char *decode(char *ciphertext, unsigned long key);

char *decode(char *ciphertext, unsigned long key) {

	int size{0};
	if (ciphertext[0] == '\0') { // accounts for if first character of ciphertext was a null character
		size = 0;
	} else {
		for (int x{0}; ciphertext[x] != '\0'; x++) {
			size = x;
		}
		size += 1;
	} // determines size of ciphertext

	int numgroups;
	numgroups = size/5; // determines number of groups of 5

	char *nonasciiarmor = new char[(size*4/5)]; // new array to store non ascii armor version of ciphertext
	int binaryform[32];
	unsigned int total {0};
	unsigned int num {0};

	for (int x{0}; x <= numgroups - 1; x++) { // separates the ciphertext into groups of 5

		total = 0;

		for (int y{0}; y <= 4; y++) { // each char in the group of 5 is converted and added to a 32-bit integer
			total += (ciphertext[y + x*5] - 33) * pow(85, (4 - y));
		}

		for (int b{31}; b >= 0; b--) { //dec converted to binary and stored in an array
			binaryform[b] = total%2;
			total = total/2;
		}

		for (int z{0}; z <= 3; z++) { // the 32 bit is split into 4 parts
			num = 0;

			for (int c{0}; c <= 7; c++){ // each 4 parts is converted to its own dec number
				num += binaryform[(c + z*8)] * pow(2, (7 - c));
			}

			nonasciiarmor[z + x*4] = num; //the num is stored as a char in the non ascii armor array
		}
	}

	int s[256];

	for (int k{0}; k <= 255; k++) {
		s[k] = k;
	} // initializes array s[] with s[k] = k from 0 to 255

	int i{0};
	int j{0};
	int k, kthbit, r, temp;
	unsigned long shift;
	int *Rvalues = new int[(size*4/5)];
	char *plaintext = new char[(size*4/5)];

	for (int x{0}; x <= 255; x++) {
		k = i%64;

		shift = key >> k; // shifts the kth bit to the 0th bit
		kthbit = shift & 1; // bitwise AND operator with 1 to determine if kthbit is 1 or 0

		j = (j + s[i] + kthbit)%256;
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;
		i = (i + 1)%256;
	}

	for (int x{0}; x <= (size*4/5 - 1); x++) {
		i = (i + 1)%256;
		j = (j + s[i])%256;
		temp = s[j];
		s[j] = s[i];
		s[i] = temp;
		r = (s[i] + s[j])%256;
		Rvalues[x] = s[r]; // stores s[r] into an array of Rvalues <- not necessary but for clarity
		plaintext[x] = Rvalues[x]^nonasciiarmor[x]; // xor with the nonasciiarmor to get plaintext
	}

	return plaintext;
}



int main();

int main() {
	char plaintext[]{"l=]V]&9\"J?rOu*9"};
	unsigned long key{51323};
	std::cout << decode(plaintext, key) << std::endl;
	char text[]{"Hello World!"};
	std::cout << encode(text, key);
	return 0;
}

