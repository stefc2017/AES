/**********
 * aesStefanCouture.c - Assignment 3
 * Stefan Couture, Student number: 7771638
 * COMP 4140, Fall 2018
 * userId: coutures
 **********/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "aesStefanCouture.h"

/*
 * main
 * This method is the main method of the program. Everything starts here.
 */
int main(int argc, char *argv[]){
  
   FILE *sboxFilePtr;
   FILE *inverseSboxFilePtr;
   FILE *keyPtr;
   FILE *plaintextPtr;
   
   plaintextPtr = fopen(argv[1], "r");
   keyPtr = fopen(argv[2], "r");
   sboxFilePtr = fopen(argv[3], "r");
   inverseSboxFilePtr = fopen(argv[4], "r");

   if(!plaintextPtr){
      printf("%s %s", "An error occurred trying to open\n", argv[1]);
      exit(-1);
   }
   if(!keyPtr){
      printf("%s %s", "An error occurred trying to open\n", argv[2]);
      exit(-1);
   }
   else if(!sboxFilePtr){
      printf("%s %s", "An error occurred trying to open\n", argv[3]);
      exit(-1);
   }
   else if(!inverseSboxFilePtr){
      printf("%s %s", "An error occurred trying to open\n", argv[4]);
      exit(-1);
   }

   matrix cipher, plain, master_key, s_box, inverse_s_box;
   
   word message[1][16]; //1 row of 16 bytes
   word masterKey[1][16]; //1 row of 16 bytes
   word sbox[16][16]; //16 rows of 16 bytes
   word inverseSbox[16][16]; //16 rows of 16 bytes
   word keySchedule[1][KEY_SCHEDULE_SIZE]; //Nb * (Nr + 1) keys

   memset(cipher.matrix, 0, sizeof(matrix));
   memset(plain.matrix, 0, sizeof(matrix));
   memset(master_key.matrix, 0, sizeof(matrix));
   memset(s_box.matrix, 0, sizeof(matrix));
   memset(inverse_s_box.matrix, 0, sizeof(matrix));

   memset(message, 0, sizeof(word) * 16);
   memset(masterKey, 0, sizeof(word) * 16);
   memset(sbox, 0, sizeof(word) * 16 * 16);
   memset(inverseSbox, 0, sizeof(word) * 16 * 16);
   memset(keySchedule, 0, sizeof(word) * KEY_SCHEDULE_SIZE);

   initializeStruct(plaintextPtr, message);
   initializeStruct(keyPtr, masterKey);
   initializeStruct(sboxFilePtr, sbox);
   initializeStruct(inverseSboxFilePtr, inverseSbox);
   
   plain = createMatrix(message, 'm', 4, 4);
   master_key = createMatrix(masterKey, 'c', 1, 16);
   s_box = createMatrix(sbox, 's', 16, 16);
   inverse_s_box = createMatrix(inverseSbox, 's', 16, 16);
   inverse_s_box = createMatrix(inverseSbox, 's', 16, 16);

   printf("Plaintext Filename: %s", argv[1]);
   printf("\nKey Filename: %s\n", argv[2]);

   printf("\nmaster Key: ");
   printMatrix(master_key, 1, 16);
   
   generateKeySchedule(masterKey, keySchedule, s_box);

   printf("key schedule: \n");
   printKeySchedule(keySchedule);
   
   printf("\nENCRYPTION PROCESS \n------------------\n");
   printf("plaintext: \n");
   printMatrix(plain, 4, 4);

   cipher = encrypt(plain, keySchedule, s_box);

   printf("Ciphertext: \n");
   printMatrix(cipher, 4, 4);

   printf("\nDECRYPTION PROCESS \n------------------\n");
   printf("Ciphertext: \n");
   printMatrix(cipher, 4, 4);

   plain = decrypt(cipher, keySchedule, inverse_s_box);

   printf("Plaintext: \n");
   printMatrix(plain, 4, 4);
   
   fclose(plaintextPtr);
   fclose(keyPtr);
   fclose(inverseSboxFilePtr);
   fclose(sboxFilePtr);
 return 0;
}//end main

/*
 * addRoundKey
 * This method will take 2 matrix structs and then, add the roundKey to the state via an xor.
 */
matrix addRoundKey(matrix state, matrix roundKey){
   matrix result;
   memset(result.matrix, 0, sizeof(matrix));
   result = xorMatrices(state, roundKey);
   return result;
}//end addRoundKey

/*
 * convertHexCharToInt
 * This method will take a char hex value and go through my custom hash map struct and return
 * the hex's decimal representation.
 */
int convertHexCharToInt(char hex){
   int i, intValue;
   hmap hexToInt[16] = {{"0", 0}, {"1", 1}, {"2", 2}, {"3", 3}, {"4", 4}, {"5", 5}, {"6", 6}, {"7", 7}, {"8", 8},   {"9", 9}, {"a", 10}, {"b", 11}, {"c", 12}, {"d", 13}, {"e", 14}, {"f", 15}};

   for(i = 0; i < 16; i++){
      if(hexToInt[i].key[0] == hex){
         intValue = hexToInt[i].value;
         break;
      }
   }
   return intValue;
}//end convertHexCharToInt

/*
 * createMatrix
 * This method will take a word array and convert it into a matrix array of size rows * cols
 */
matrix createMatrix(word src[][16], char type, int rows, int cols){
   int r,c,i;
   matrix result;

   i = 0;
   memset(result.matrix, 0, sizeof(matrix));
   
   if(type == 's'){ //if the input is a sbox or inverse s box
      for(r = 0; r < rows; r++){
         for(c = 0; c < cols; c++){
            strncpy(result.matrix[r][c].hex, src[r][c].hex, 2);
         }
      }
   } 
   else { //anything else
      for(c = 0; c < cols; c++){
         for(r = 0; r < rows; r++){
            strncpy(result.matrix[r][c].hex, src[0][i].hex, 2);
            i++;
         }
      }
   }
   return result;
}//end createMatrix

/*
 * createRoundKeyMatrix
 * This method will take a keySchedule word 2d-array and create and return a 4x4 matrix
 */
matrix createRoundKeyMatrix(word keySchedule[][KEY_SCHEDULE_SIZE], int startFrom){
   int r,c,i;
   char currentHexString[9], hex[2];
   matrix result;

   i = startFrom;
   memset(result.matrix, 0, sizeof(matrix));

   for(c = 0; c < 4; c++){
      strncpy(currentHexString, keySchedule[0][i].hex, 8);
      for(r = 0; r < Nb; r++){
         hex[0] = currentHexString[2*r];
         hex[1] = currentHexString[2*r+1];
         strncpy(result.matrix[r][c].hex, hex, 2);
      }
      i++;
   }
   return result;
}//end createRoundKeyMatrix

/*
 * decrypt
 * This method will take a ciphertext, a key schedule and an inverse sbox. 
 * It will decrypt the ciphertext and return a matrix of the plaintext message.
 */
matrix decrypt(matrix ciphertext, word keySchedule[][KEY_SCHEDULE_SIZE], matrix inverse_sbox){
   matrix state, roundKey, mixCol;
   int round;
   int nextIndex = 40; //next index for keySchedule, keep track of where we are

   memset(mixCol.matrix, 0, sizeof(matrix));
   memset(state.matrix, 0, sizeof(matrix));
   memset(roundKey.matrix, 0, sizeof(matrix));

   mixCol = initializeMixColumnMatrix(mixCol, 'i');
   state = ciphertext;

   roundKey = createRoundKeyMatrix(keySchedule, nextIndex);
   nextIndex -= 4;

   state = addRoundKey(state, roundKey);
   
   for(round = Nr-1; round >= 1; round--){
      printf("Round %d \n--------\n", round);
      printMatrix(state, 4, 4);

      state = invShiftRows(state);
      state = subBytes(state, inverse_sbox); //use same function, just pass inverse sbox
      
      /*Get roundKey and add it to addRoundKey*/
      roundKey = createRoundKeyMatrix(keySchedule, nextIndex);
      nextIndex-=4;
      state = addRoundKey(state, roundKey);

      state = mixColumns(state, mixCol);
   }
   
   printf("Round 0 \n--------\n");
   printMatrix(state, 4, 4);

   state = invShiftRows(state);
   state = subBytes(state, inverse_sbox); //use same function, just pass inverse sbox

   /*Get roundKey and add it to addRoundKey*/
   roundKey = createRoundKeyMatrix(keySchedule, nextIndex);
   nextIndex-=4;
   state = addRoundKey(state, roundKey);

   return state;
}//end decrypt

/*
 * encrypt
 * This method will take a plaintext, a key schedule and an sbox. 
 * It will encrypt the plaintext and return a matrix of the ciphertext message.
 */
matrix encrypt(matrix plaintext, word keySchedule[][KEY_SCHEDULE_SIZE], matrix sbox){
   matrix state, roundKey, mixCol;
   int round;
   int nextIndex = 0; //next index for keySchedule, keep track of where we are

   memset(mixCol.matrix, 0, sizeof(matrix));
   memset(state.matrix, 0, sizeof(matrix));
   memset(roundKey.matrix, 0, sizeof(matrix));

   mixCol = initializeMixColumnMatrix(mixCol, 'r');
   state = plaintext;

   roundKey = createRoundKeyMatrix(keySchedule, nextIndex);
   nextIndex += 4;

   state = addRoundKey(state, roundKey);
   
   for(round = 1; round <= Nr-1; round++){
      printf("Round %d \n--------\n", round);
      printMatrix(state, 4, 4);

      state = subBytes(state, sbox);
      state = shiftRows(state);
      state = mixColumns(state, mixCol);
      
      /*Get roundKey and add it to addRoundKey*/
      roundKey = createRoundKeyMatrix(keySchedule, nextIndex);
      nextIndex+=4;
      state = addRoundKey(state, roundKey);  
   }
   
   printf("Last Round \n--------\n");
   printMatrix(state, 4, 4);

   state = subBytes(state, sbox);
   state = shiftRows(state);

   /*Get roundKey and add it to addRoundKey*/
   roundKey = createRoundKeyMatrix(keySchedule, nextIndex);
   nextIndex+=4;
   state = addRoundKey(state, roundKey);

   return state;
}//end encrypt

/*
 * generateKeySchedule
 * This method will take a masterKey, a 2d-array of word and an sbox matrix and
 * it will create and store the keySchedule in the words parameter which is a pointer
 * to the 2d-array that was passed in.
 */
void generateKeySchedule(word masterKey[][16], word words[][KEY_SCHEDULE_SIZE], matrix sbox){
   word temp = {{0}};
   int i = 0;
   
   while(i < Nk){
      strcat(words[0][i].hex, masterKey[0][4*i].hex);
      strcat(words[0][i].hex, masterKey[0][4*i+1].hex);
      strcat(words[0][i].hex, masterKey[0][4*i+2].hex);
      strcat(words[0][i].hex, masterKey[0][4*i+3].hex);
      i++;
   }//end while

   i = Nk;

   while(i < KEY_SCHEDULE_SIZE){
      temp = words[0][i-1];

      if(i % Nk == 0){
         temp = xorWords(subWord(rotWord(temp), sbox), rcon(i/Nk));
      }
      else if(Nk > 6 && i % Nk == 4){
         temp = subWord(temp, sbox);
      }
      words[0][i] = xorWords(words[0][i-Nk], temp);
      i++;
   }
}//end generateKeySchedule

/*
 * initializeMixColumnMatrix
 * This method will take a destination matrix and a char type saying whether we are creating
 * a regular mix column matrix (for encryption) or an inverse (for decryption). It will return
 * the formed matrix.
 */
matrix initializeMixColumnMatrix(matrix dest, char type){
   if(type == 'r'){ //regular (non-inverse)
      strncpy(dest.matrix[0][0].hex, "02", 2); strncpy(dest.matrix[0][1].hex, "03", 2);
      strncpy(dest.matrix[1][0].hex, "01", 2); strncpy(dest.matrix[1][1].hex, "02", 2);
      strncpy(dest.matrix[2][0].hex, "01", 2); strncpy(dest.matrix[2][1].hex, "01", 2);
      strncpy(dest.matrix[3][0].hex, "03", 2); strncpy(dest.matrix[3][1].hex, "01", 2);
   
      strncpy(dest.matrix[0][2].hex, "01", 2); strncpy(dest.matrix[0][3].hex, "01", 2);
      strncpy(dest.matrix[1][2].hex, "03", 2); strncpy(dest.matrix[1][3].hex, "01", 2);
      strncpy(dest.matrix[2][2].hex, "02", 2); strncpy(dest.matrix[2][3].hex, "03", 2);
      strncpy(dest.matrix[3][2].hex, "01", 2); strncpy(dest.matrix[3][3].hex, "02", 2);
   }
   else if(type == 'i'){ //inverse
      strncpy(dest.matrix[0][0].hex, "0e", 2); strncpy(dest.matrix[0][1].hex, "0b", 2);
      strncpy(dest.matrix[1][0].hex, "09", 2); strncpy(dest.matrix[1][1].hex, "0e", 2);
      strncpy(dest.matrix[2][0].hex, "0d", 2); strncpy(dest.matrix[2][1].hex, "09", 2);
      strncpy(dest.matrix[3][0].hex, "0b", 2); strncpy(dest.matrix[3][1].hex, "0d", 2);
   
      strncpy(dest.matrix[0][2].hex, "0d", 2); strncpy(dest.matrix[0][3].hex, "09", 2);
      strncpy(dest.matrix[1][2].hex, "0b", 2); strncpy(dest.matrix[1][3].hex, "0d", 2);
      strncpy(dest.matrix[2][2].hex, "0e", 2); strncpy(dest.matrix[2][3].hex, "0b", 2);
      strncpy(dest.matrix[3][2].hex, "09", 2); strncpy(dest.matrix[3][3].hex, "0e", 2);
   }
   return dest;
}//end initializeMixColumnMatrix

/*
 * initializeStruct
 * This method will take a file pointer and a destination 2d array. It will
 * pull the data from the input files and parse it into a 2d-array.
 */
void initializeStruct(FILE *file, word dest[][16]){
   char ch;
   char previousChar;
   int row = 0;
   int col = 0;

   while ((ch = getc(file)) != EOF){
      if(ch == '\n'){
         row++;
	 col = 0;
      }
      //if not space, then add char
      else if(ch != ' '){
         if(previousChar == ' '){
	    col++;
         }
	 word temp = dest[row][col];
         dest[row][col].hex[temp.index] = ch; //update hex value for current s-box index
	 dest[row][col].index = temp.index + 1;
      }
      previousChar = ch;   
   }
}//end initializeStruct

/*
 * invShiftRows
 * This method will take a input matrix and perform the inverse shift
 * rows on it for aes decryption and return that matrix.
 */
matrix invShiftRows(matrix input){
   matrix result;
   int c, i, r;
   memset(result.matrix, 0, sizeof(matrix));

   i = 0;
   
   for(c = 0; c < 4; c++){
      for(r = 0; r < 4; r++){
         i = ( c + r) % 4;
         strncpy(result.matrix[r][i].hex, input.matrix[r][c].hex, 2);
      }
   }
   return result;
}//end invShiftRows

/*
 * mixColumns
 * This method will take the input matrix to mix its columns and
 * the mix columns matrix (temp) and return the mixed columns matrix.
 */
matrix mixColumns(matrix input, matrix temp){ 
   matrix result;
   char multResult[3], xorResult[3];
   int c, i, j;

   memset(result.matrix, 0, sizeof(matrix));
   
   for(c = 0; c < 4; c++){
      for(i = 0; i < 4; i++){
         for(j = 0; j < 4; j++){
            multiply(multResult, input.matrix[j][c].hex, temp.matrix[i][j].hex);
            if(j == 0){
               strncpy(xorResult, multResult, 2);
            }
            else if(j != 0){
               word xorRslt = xorHexCharacters(xorResult, multResult);
               strncpy(xorResult, xorRslt.hex, 2);
            }
         }
         strncpy(result.matrix[i][c].hex, xorResult, 2);
      }
   }
  
   return result;
}//end mixColumns

/*
 * multiply
 * This method will take a destination string to store the multiplication result
 * as well as two hex strings of 2 values and multiply them together (elem1, elem2)
 */
void multiply(char dest[2], char elem1[2], char elem2[2]){
   unsigned int el1 = (unsigned int)strtol(elem1, NULL, 16);
   unsigned int el2 = (unsigned int)strtol(elem2, NULL, 16);
   unsigned int result = 0;

	while (el1 && el2) {
            if (el2 & 1){
                result ^= el1; 
            }
            if (el1 & 0x80){ //check for int overflow
                el1 = (el1 << 1) ^ 0x11b;  
            }
            else{
                el1 <<= 1; //like saying el1 * 2
            }
            el2 >>= 1; //like saying el2 / 2
	}
        sprintf(dest, "%02x", result);
}//end multiply

/*
 * printKeySchedule
 * This method will take a keySchedule to print out such that 4
 * keys are printed per line.
 */
void printKeySchedule(word keySchedule[][KEY_SCHEDULE_SIZE]){
   int i;

   for(i=0; i < KEY_SCHEDULE_SIZE; i++){
     
         if( i != 0 && (i+1) % 4 == 0){
            printf("%s\n", keySchedule[0][i].hex);
         }
         else{
            printf("%s,", keySchedule[0][i].hex);
         }
      }
}//end printKeySchedule

/*
 * printMatrix
 * This method will take a matrix to print as well as its dimensions 
 * denoted by the int rows and cols.
 */
void printMatrix(matrix mat, int rows, int cols){
   int r,c;

   for(c=0; c < cols; c++){
     for(r=0; r < rows; r++){
        printf("%s ", mat.matrix[r][c].hex);  
     }
   }
   printf("\n\n");
}//end printMatrix

/*
 * rcon
 * This method will take a int value and return a rcon hex string.
 */
word rcon(int index){
   word rconResult = {{0}};
   //need only the first 10 since i/Nk = 40/4 = 10 (last multiple of 4 before 43 - last index of i)
   char *rconArray[11] = {NULL, "01000000", "02000000", "04000000", "08000000", "10000000", "20000000", "40000000", "80000000", "1b000000", "36000000"};
   strncpy(rconResult.hex, rconArray[index], 8);
   return rconResult;
}//end rcon

/*
 * rotWord
 * This method will take a word and apply a cyclic permutation on it
 * as described in the aes spec and then return the word.
 */
word rotWord(word keyWord){
   word temp;
   int i;

   //temp contains keyWord[0]
   temp.hex[0] = keyWord.hex[0];
   temp.hex[1] = keyWord.hex[1];

   for(i = 0; i < 4; i++){
      if(i != 3){
         keyWord.hex[2*i] = keyWord.hex[2*(i+1)];
         keyWord.hex[2*i+1] = keyWord.hex[2*(i+1)+1];
      }
      else{
         keyWord.hex[2*i] = temp.hex[0];
         keyWord.hex[2*i+1] = temp.hex[1];
      }
   }
   return keyWord;
}//end rotWord

/*
 * shiftRows
 * This method will take a matrix and shift row i by i places to the left
 * and return the matrix.
 */
matrix shiftRows(matrix input){
   matrix result;
   int c, i, r;

   i = 0;
   memset(result.matrix, 0, sizeof(matrix));
   
   for(c = 0; c < 4; c++){
      for(r = 0; r < 4; r++){
         i = (c + r) % 4;
         strncpy(result.matrix[r][c].hex, input.matrix[r][i].hex, 2);
      }
   }
   return result;
}//end shiftRows

/*
 * subBytes
 * This method will take a input matrix and an sbox matrix. It will use
 * the sbox to substitute each two hex characters (each byte) and then
 * return a matrix.
 */
matrix subBytes(matrix input, matrix sbox){
   char hex[3];
   int r,c,row,col;
   matrix returnMatrix;

   memset(returnMatrix.matrix, 0, sizeof(matrix));

   for(c = 0; c < 4; c++){
      for(r = 0; r < 4; r++){
         row = convertHexCharToInt(input.matrix[r][c].hex[0]);
         col = convertHexCharToInt(input.matrix[r][c].hex[1]);
         strncpy(hex, sbox.matrix[row][col].hex, 2);
         strncpy(returnMatrix.matrix[r][c].hex, hex, 2);
      }
   }
   return returnMatrix;
}//end subBytes

/*
 * subWord
 * This method will take a word and apply the sbox substitution to it.
 */
word subWord(word keyWord, matrix sbox){
   word result = {{0}};
   word newWord = {{0}};
   int i;

   for(i = 0; i < 4; i++){
      int row = convertHexCharToInt(keyWord.hex[2*i]);
      int col = convertHexCharToInt(keyWord.hex[2*i+1]);
      result = sbox.matrix[row][col];
      strcat(newWord.hex, result.hex);
   }
   return newWord;
}//end subWord

/*
 * xorHexCharacters
 * This method will two hex strings of length 2 and xor them together.
 */
word xorHexCharacters(char hex1[2], char hex2[2]){
   char temp1[2], temp2[2];
   int numHex1 = 0; int numHex2 = 0;
   word xorResult = {{0}};
   word result = {{0}}; 
   int i;

   memset(temp1, 0, sizeof(char) * 2);
   memset(temp2, 0, sizeof(char) * 2);

   for(i = 0; i < 2; i++){
      temp1[0] = hex1[i]; temp1[1] = '\0';
      temp2[0] = hex2[i]; temp2[1] = '\0';
      
      numHex1 = (int)strtol(temp1, NULL, 16);
      numHex2 = (int)strtol(temp2, NULL, 16);
      
      sprintf(xorResult.hex, "%x", numHex1 ^ numHex2);
      strcat(result.hex, xorResult.hex);
   }
   
   return result;
}//end xorHexCharacters

/*
 * xorMatrices
 * This method will two matrices and xor them together.
 */
matrix xorMatrices(matrix dest, matrix src){
   int r,c,s, numHex1, numHex2;
   char hex1[2], hex2[2], xor[2], result[2];
   matrix xorResult;

   memset(xorResult.matrix, 0, sizeof(matrix));
   numHex1 = 0; numHex2 = 0;

   for(c=0; c < 4; c++){
     for(r=0; r < 4; r++){
       memset(result, 0, sizeof(result) * 2);
       for(s=0; s < 2; s++){
          hex1[0] = dest.matrix[r][c].hex[s]; hex1[1] = '\0';
          hex2[0] = src.matrix[r][c].hex[s]; hex2[1] = '\0';
          numHex1 = (int)strtol(hex1, NULL, 16);
          numHex2 = (int)strtol(hex2, NULL, 16);
          sprintf(xor, "%x", numHex1 ^ numHex2);
          strcat(result, xor);
       }
       strncpy(xorResult.matrix[r][c].hex, result, 2);
     }
   }
   
   return xorResult;
}//end xorMatrices

/*
 * xorWords
 * This method will take two word and xor them together.
 */
word xorWords(word word1, word word2){
   char hex1[2], hex2[2];
   int numHex1 = 0; int numHex2 = 0; int i;
   word xorResult = {{0}};
   word result = {{0}};
   
   for(i = 0; i < 8; i++){
      hex1[0] = word1.hex[i]; hex1[1] = '\0';
      hex2[0] = word2.hex[i]; hex2[1] = '\0';

      numHex1 = (int)strtol(hex1, NULL, 16);
      numHex2 = (int)strtol(hex2, NULL, 16);

      sprintf(xorResult.hex, "%x", numHex1 ^ numHex2);
      strcat(result.hex, xorResult.hex);
   }
   
   return result;
}//end xorWords
