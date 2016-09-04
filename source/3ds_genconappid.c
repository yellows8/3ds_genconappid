#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "polarssl/sha2.h"

int main(int argc, char **argv)
{
	unsigned char hashdata[12];
	unsigned char hash[32];

	unsigned long long *condata = (unsigned long long*)&hashdata[0];
	unsigned int *saltdata = (unsigned int*)&hashdata[8];
	unsigned long long *outid = (unsigned long long*)&hash[24];

	*condata = 0;
	*saltdata = 0;

	if(argc<3)
	{
		printf("3ds_genconappid v1.0 by yellows8\n");
		printf("generate the 8-byte 'id' which the 3DS cfg module generates, from 8-byte console-unique data and a 20bit salt. aka Cfg:GenHashConsoleUnique/GetTransferableId.\n");
		printf("Usage:\n3ds_genconappid <20bithexsalt> <conuniquehexdata>\n");
		return 0;
	}

	if(strlen(argv[1])!=5 || strlen(argv[2])!=16)
	{
		printf("invalid input\n");
		return 0;
	}

	sscanf(argv[1], "%05x", saltdata);
	sscanf(argv[2], "%16llx", condata);
	*saltdata &= 0xfffff;
	printf("using condata/saltdata: %16llx %05x\n", *condata, *saltdata);

	memset(hash, 0, 32);
	sha2(hashdata, 12, hash, 0);
	printf("outid: %16llx\n", *outid);

	return 0;
}

