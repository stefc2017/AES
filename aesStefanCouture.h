/**********
 * aesStefanCouture.h - Assignment 3
 * Stefan Couture, Student number: 7771638
 * COMP 4140, Fall 2018
 * userId: coutures
 **********/

#ifndef AES_STEFAN_COUTURE

#define AES_STEFAN_COUTURE
#define Nk 4  //key length
#define Nb 4  //block size
#define Nr 10 //number of rounds
#define KEY_SCHEDULE_SIZE Nb * (Nr+1)

struct WORD {
   char hex[8]; // 4 bytes (8 hex)
   int index;
};

struct MATRIX {
   struct WORD matrix[16][16];
};

struct HASHMAP {
   char key[1];
   int value;
};

typedef struct WORD word;
typedef struct MATRIX matrix;
typedef struct HASHMAP hmap;

int main(int argc, char *argv[]);

matrix addRoundKey(matrix state, matrix roundKey);
int convertHexCharToInt(char hex);
matrix createMatrix(word src[][16], char type, int rows, int cols);
matrix createRoundKeyMatrix(word keySchedule[][KEY_SCHEDULE_SIZE], int startFrom);
matrix decrypt(matrix ciphertext, word keySchedule[][KEY_SCHEDULE_SIZE], matrix inverse_sbox);
matrix encrypt(matrix plaintext, word keySchedule[][KEY_SCHEDULE_SIZE], matrix sbox);
void generateKeySchedule(word masterKey[][16], word words[][KEY_SCHEDULE_SIZE], matrix sbox);
matrix initializeMixColumnMatrix(matrix dest, char type);
void initializeStruct(FILE *file, word dest[][16]);
matrix invShiftRows(matrix input);
matrix mixColumns(matrix input, matrix temp);
void multiply(char dest[2], char elem1[2], char elem2[2]);
void printKeySchedule(word keySchedule[][KEY_SCHEDULE_SIZE]);
void printMatrix(matrix mat, int rows, int cols);
word rcon(int index);
word rotWord(word keyWord);
matrix shiftRows(matrix input);
matrix subBytes(matrix input, matrix sbox);
word subWord(word keyWord, matrix sbox);
word xorHexCharacters(char hex1[2], char hex2[2]);
matrix xorMatrices(matrix dest, matrix src);
word xorWords(word word1, word word2);
#endif
