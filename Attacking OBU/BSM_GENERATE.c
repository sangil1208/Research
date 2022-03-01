#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

#define REPT 640

unsigned char cert[512] = { 0x00, };
unsigned char certOutput[SHA256_DIGEST_LENGTH];
unsigned char* ptrCert;
//0x40,0x03,0x80,0x28,0x00,0x14,0x25,0x0d,0xcb,0x9f,0xe2,0x5d,0xdf,0xfc,0x1a,0xd2,0x76,0x42,0x35,0xa4,0xf7,0x0a,0x87,0xa6,0x7f,0xff,0x80,0x00,0x71,
//0xed, 0x1c, 0x20, 0x7e, 0x8c, 0xa7, 0xcf, 0x4d, 0x7f, 0xff, 0x02, 0xaa, 0x5d, 0x0f, 0x50, 0x40, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x21, 0x19, 0xb4, 0x65
unsigned char tbsData[512] = { "" };
unsigned char tbsDataOutput[SHA256_DIGEST_LENGTH];
unsigned char* ptrTbsData;

int certCount = 0;
int tbsDataCount = 55;

unsigned char signKey[65];            // signKey from *.s File (32 Byte)
unsigned char* r_value = NULL;         // r value from ECDSA signature
unsigned char* s_value = NULL;         // s value from ECDSA signature

int cnt = 0;
int gcnt = 0;
int MsgCnt = 0;

//함수 호출 순서
//0.pem파일 만들기
//1.generation time 변경
//2.tbsData추출
//3.signature생성, r,s뽑기
//4.생성한 signature로 변경

void signatureChange(int type, char* r, char* s);
void modifyGenerationtime(int type);
void getTbsDataInByteArray();
void GenerateECDSASignature();
void LoadCertFile();
void LoadKeyFile();


unsigned char hexBasicCert[228][5] = {
"0x0b", "0x03", "0x0f", "0x01", "0xac", "0x10", "0x01", "0x0c", "0x04", "0x01", "0x95", "0x00", "0x20", "0x80", "0xd5", "0x03",
"0x81", "0x00", "0x40", "0x03", "0x80", "0x28", "0x00", "0x14", "0x25", "0x0d", "0xcb", "0x9f", "0xe2", "0x5d", "0xdf", "0xfc",
"0x1a", "0xd2", "0x76", "0x42", "0x35", "0xa4", "0xf7", "0x0a", "0x87", "0xa6", "0x7f", "0xff", "0x80", "0x00", "0x71", "0xed",
"0x1c", "0x20", "0x7e", "0x8c", "0xa7", "0xcf", "0x4d", "0x7f", "0xff", "0x02", "0xaa", "0x5d", "0x0f", "0x50", "0x40", "0x01",
"0x20", "0x00", "0x00", "0x00", "0x00", "0x21", "0x19", "0xb4", "0x65", "0x81", "0x01", "0x01", "0x00", "0x03", "0x01", "0x80",
"0x62", "0x08", "0xe0", "0x2b", "0x40", "0x2d", "0x2b", "0xc5", "0x50", "0x80", "0x00", "0x00", "0x5e", "0x82", "0xa8", "0x82",
"0x7f", "0x15", "0x5f", "0x30", "0x6b", "0x47", "0x80", "0xc3", "0xcf", "0x00", "0x01", "0x21", "0x09", "0x62", "0xa5", "0x84",
"0x00", "0xa9", "0x83", "0x01", "0x01", "0x80", "0x01", "0x9a", "0x01", "0x02", "0x00", "0x01", "0x20", "0x00", "0x01", "0x26",
"0x81", "0x82", "0x05", "0x21", "0xf3", "0x09", "0xb3", "0x9f", "0x0e", "0x16", "0x7f", "0x6c", "0x82", "0xcb", "0x5e", "0x92",
"0x93", "0x9b", "0xf5", "0xa5", "0x3b", "0x61", "0x03", "0xbe", "0x3b", "0xca", "0xa7", "0x65", "0x27", "0x29", "0xfb", "0xb0",
"0x80", "0xf4", "0x80", "0x80", "0xdc", "0xc3", "0xfc", "0xd3", "0xfc", "0x34", "0x3c", "0x69", "0xc0", "0x90", "0x19", "0xbf",
"0xc8", "0xaa", "0x5c", "0x14", "0xcd", "0x48", "0xf7", "0xa4", "0x8e", "0xf2", "0x8c", "0x13", "0x2e", "0x81", "0x06", "0xb8",
"0xf1", "0x43", "0xeb", "0xdb", "0xd2", "0x57", "0x5a", "0xcf", "0x11", "0x15", "0x0d", "0x30", "0x87", "0xce", "0x80", "0x66",
"0x29", "0x57", "0x85", "0xbf", "0xae", "0xf9", "0x85", "0xad", "0xb5", "0xbd", "0xf9", "0xd8", "0xa9", "0x65", "0x57", "0xfb",
"0x28", "0xe5", "0x5c", "0x6b" };

unsigned char hexBasicDigest[148][5] = {
"0x0b", "0x03", "0x0f", "0x01", "0xac", "0x10", "0x01", "0x0c", "0x04", "0x01", "0x95", "0x00", "0x20", "0x80", "0x85", "0x03",
"0x81", "0x00", "0x40", "0x03", "0x80", "0x28", "0x00", "0x14", "0x25", "0x0c", "0xcb", "0x9f", "0xe2", "0x5d", "0xdf", "0x96",
"0x5a", "0xd2", "0x76", "0x42", "0x35", "0xa4", "0xf5", "0xac", "0x07", "0xa6", "0x7f", "0xff", "0x80", "0x00", "0x71", "0xd8",
"0x1c", "0x20", "0x7e", "0x8c", "0xa7", "0xcf", "0x4d", "0x7f", "0xff", "0x02", "0xaa", "0x5d", "0x0f", "0x50", "0x40", "0x01",
"0x20", "0x00", "0x00", "0x00", "0x00", "0x21", "0x19", "0xb4", "0x65", "0x80", "0xf9", "0xd2", "0x27", "0xb0", "0x52", "0xbe",
"0x7c", "0xc0", "0x80", "0x80", "0xc0", "0x2b", "0xac", "0x2d", "0x55", "0x6f", "0x32", "0x44", "0xed", "0x4e", "0x15", "0x35",
"0x89", "0xae", "0x38", "0xc3", "0xcd", "0xdd", "0x7d", "0xd7", "0x46", "0x12", "0xfe", "0x4d", "0x7a", "0x5f", "0x7e", "0x79",
"0x38", "0x93", "0x3b", "0x70", "0x0c", "0x7d", "0x5a", "0x0e", "0x65", "0xad", "0xe7", "0xea", "0x81", "0xa1", "0xf3", "0xb5",
"0x1d", "0xbf", "0x3f", "0x4e", "0xd9", "0x24", "0x30", "0x17", "0xb3", "0xc5", "0x2b", "0x5b", "0x58", "0x12", "0xb9", "0x67",
"0x0a", "0x0b", "0x2c", "0x86" };

void LoadKeyFile() {
	FILE* fp = fopen("/home/user/key.s", "rb");
	unsigned char temp[3];
	int ch;
	int i = 0;
	while ((ch = fgetc(fp)) != EOF) {
		sprintf(temp, "%02x", ch);
		signKey[i++] = temp[0];
		signKey[i++] = temp[1];
	}
	fclose(fp);
}

void ChangeMsgCnt(int qwe) {
	char temp[4] = { "000" };
	int num = 0;
	qwe = qwe % 128;
	int flag = 0 ;

	for (int i = 0; i < qwe + 1; i++) {
		char last[4] = { '1', '5', '9', 'd' };
		temp[2] = last[i % 4];
		if (i % 4 == 0 && i != 0) {
			num += 1;
			char asd[4] = "";
			sprintf(asd, "%x", num);
			temp[1] = asd[1];
			if (strlen(asd) == 1) {
				temp[1] = asd[0];
			}
		}
		if (flag == 1){
			temp[0] = '1';
			flag = 0;	
		}
		if (strcmp(temp, "0fd") == 0) {
			flag = 1;
		}
	}

	hexBasicCert[25][2] = temp[0];
	hexBasicCert[25][3] = temp[1];
	hexBasicCert[26][2] = temp[2];
	hexBasicDigest[25][2] = temp[0];
	hexBasicDigest[25][3] = temp[1];
	hexBasicDigest[26][2] = temp[2];

}

void LoadCertFile() {
	FILE* fp = fopen("/home/user/certificate.cert", "rb");
	ptrCert = cert;
	while (!feof(fp))
	{
		fread(ptrCert++, 1, 1, fp);
		certCount++;
	}
	certCount--;
	char temp[3];
	for (int i = 0; i < certCount; i++) {
		char base[5] = "0x";
		sprintf(temp, "%02x", cert[i]);
		strcat(base, temp);
		memcpy(&hexBasicCert[76 + i], base, 5);
	}
	fclose(fp);
}


void modifyGenerationtime(int type) {

	time_t sec;
	time(&sec);

	long long decimal = (sec - 1072915200);
	if ((cnt / 10) != 0)
		decimal += cnt / 10;

	char hexadecimal[2000] = "";    // 16진수로 된 문자열을 저장할 배열
	int position = 0;

	while (1)
	{
		int mod = decimal % 16;    // 16으로 나누었을 때 나머지를 구함
		if (mod < 10) // 나머지가 10보다 작으면
		{
			// 숫자 0의 ASCII 코드 값 48 + 나머지
			hexadecimal[position] = 48 + mod;
		}
		else    // 나머지가 10보다 크거나 같으면
		{
			// 나머지에서 10을 뺀 값과 영문 대문자 A의 ASCII 코드 값 65를 더함
			hexadecimal[position] = 65 + (mod - 10);
		}

		decimal = decimal / 16;    // 16으로 나눈 몫을 저장

		position++;    // 자릿수 변경

		if (decimal == 0)    // 몫이 0이되면 반복을 끝냄
			break;
	}
	// 배열의 요소를 역순으로 출력
	int j = 0;

	for (int i = position - 1; i >= 0; i -= 2)
	{
		char tmp[5] = "0x";
		char tmp2[2] = { hexadecimal[i] };
		char tmp3[2] = { hexadecimal[i - 1] };
		strcat(tmp, tmp2);
		strcat(tmp, tmp3);
		if (type == 0)
			memcpy(&hexBasicCert[69 + j], tmp, 5);
		else
			memcpy(&hexBasicDigest[69 + j], tmp, 5);
		j++;
	}
	cnt++;
}

void getTbsDataInByteArray() {

	char temp[200] = { "" };

	for (int i = 18; i <= 72; i++) {
		char t1[2] = { hexBasicCert[i][2] };
		strcat(temp, t1);
		char t2[2] = { hexBasicCert[i][3] };
		strcat(temp, t2);
	}

	char tmp[3];
	int i;
	int len = strlen(temp);
	for (i = 0; i < len / 2; i++) {
		memcpy(tmp, temp + (i * 2), 2);
		tmp[2] = 0;
		tbsData[i] = (unsigned char)strtoul(tmp, NULL, 16);
	}
}

void GenerateECDSASignature() {
	SHA256_CTX context;
	EC_KEY* ecKey = NULL;
	BIGNUM* private;
	EC_POINT* public;
	const EC_GROUP* group = NULL;

	ECDSA_SIG* signature = ECDSA_SIG_new();
	unsigned char* plaintext = "";               // input for H(tbsData) | H(signer Identifier) (H means Hash)
	unsigned char digest[SHA256_DIGEST_LENGTH];      // digest for signing (32Byte)

	// set private and public key
	private = BN_new();
	ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	group = EC_KEY_get0_group(ecKey);
	EC_KEY_generate_key(ecKey);
	BN_hex2bn(&private, signKey);
	EC_KEY_set_private_key(ecKey, private);
	public = EC_POINT_new(group);
	EC_POINT_mul(group, public, private, NULL, NULL, NULL);
	EC_KEY_set_public_key(ecKey, public);

	// generate hash for signing
	// h(tbsData)
	SHA256_Init(&context);
	SHA256_Update(&context, tbsData, tbsDataCount);
	SHA256_Final(tbsDataOutput, &context);
	OPENSSL_cleanse(&context, sizeof(context));

	// h(Cert)
	SHA256_Init(&context);
	SHA256_Update(&context, cert, certCount);
	SHA256_Final(certOutput, &context);
	OPENSSL_cleanse(&context, sizeof(context));

	// h( h(tbsData) | h(Cert) ) -> ECDSA signature input(tbsDataOutput)
	memcpy(tbsData, tbsDataOutput, 32);
	memcpy(tbsData + 32, certOutput, 32);
	SHA256_Init(&context);
	SHA256_Update(&context, tbsData, 64);
	SHA256_Final(tbsDataOutput, &context);
	OPENSSL_cleanse(&context, sizeof(context));

	// generate ECDSA signature and extract r,s
	signature = ECDSA_do_sign(tbsDataOutput, SHA256_DIGEST_LENGTH, ecKey);
	//r_value = BN_bn2hex(ECDSA_SIG_get0_r(signature));
	//s_value = BN_bn2hex(ECDSA_SIG_get0_s(signature));

	const BIGNUM* s = BN_new();
	const BIGNUM* r = BN_new();
	ECDSA_SIG_get0(signature, &r, &s);
	r_value = BN_bn2hex(r);
	s_value = BN_bn2hex(s);


	//for (int i = 0; i < 32; i++)
	//	printf("%02x", tbsDataOutput[i]);

	//printf("\n%s\n", r_value);
	//printf("\n%s\n", s_value);
}

void signatureChange(int type, char* r, char* s) {

	int j = 0;
	for (int i = 0; i <= 62; i += 2) {
		char tmp[5] = "0x";
		char tmp2[2] = { r[i] };
		char tmp3[2] = { r[i + 1] };
		strcat(tmp, tmp2);
		strcat(tmp, tmp3);
		if (type == 0) {
			memcpy(&hexBasicCert[164 + j], tmp, 5);
		}
		else
			memcpy(&hexBasicDigest[84 + j], tmp, 5);
		j++;
	}
	j = 0;
	for (int i = 0; i <= 62; i += 2) {
		char tmp[5] = "0x";
		char tmp2[2] = { s[i] };
		char tmp3[2] = { s[i + 1] };
		strcat(tmp, tmp2);
		strcat(tmp, tmp3);
		if (type == 0) {
			memcpy(&hexBasicCert[196 + j], tmp, 5);
		}
		else
			memcpy(&hexBasicDigest[116 + j], tmp, 5);
		j++;
	}

}


int main() {
	FILE* fp;

	LoadKeyFile();
	LoadCertFile();

	if (access("/home/user/bsm_basic.txt", F_OK) != -1) {
		remove("/home/user/bsm_basic.txt");
	}
	fp = fopen("/home/user/bsm_basic.txt", "a+");


	if (fp == NULL) {
		printf("[-] file open error");
	}

	srand((unsigned int)time(NULL));

	for (int i = 0; i < REPT; i++) {
		gcnt += 1;
		if (gcnt % 5 == 0) {
			ChangeMsgCnt(i);
			modifyGenerationtime(0);  //cert type change
			//tbsData bytearray로
			getTbsDataInByteArray();
			GenerateECDSASignature();
			signatureChange(0, r_value, s_value);
			for (int j = 0; j < 228; j++) {
				for (int k = 0; k < 4; k++) {
					fputc(hexBasicCert[j][k], fp);
				}
				if (j != 227) {
					fputs(", ", fp);
				}
				else {
					if (i == REPT - 1)
						;
					else
						fputs("\n", fp);
				}
			}
		}
		else {
			ChangeMsgCnt(i);
			modifyGenerationtime(1); //digest type change
			//tbsData bytearray로
			getTbsDataInByteArray();
			GenerateECDSASignature();
			signatureChange(1, r_value, s_value);
			for (int j = 0; j < 148; j++) {
				for (int k = 0; k < 4; k++) {
					fputc(hexBasicDigest[j][k], fp);
				}
				if (j != 147) {
					fputs(", ", fp);
				}
				else {
					if (i == REPT - 1)
						;
					else
						fputs("\n", fp);
				}
			}
		}

		//file 작성

	}

	fclose(fp);
}




