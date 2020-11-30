#include<stdio.h>
#include<stdlib.h>

int main()
{
	unsigned int  info[4];
	int i;
	FILE *fptr;
	
	if (NULL == (fptr = fopen("/proc/monitor_network", "r")))
	{
		printf("ERROR! Opening files");
		exit(1);
	}
	//fscanf(fptr, "%s", info);
	//fgets(info, 100, (FILE*)fptr);
	//printf("%s\n", info);
	for (i = 0; i < 4; i++)
	{
		fscanf(fptr, "%u", &info[i]);
	}
	fclose(fptr);
	for (i = 0; i < 4; i++)
	{
		printf("%u  ", info[i]);
	}
	printf("\n");
	return 0;
}
