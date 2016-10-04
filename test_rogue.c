#include <unistd.h>
#include <stdio.h>
#include <time.h>

int main()
{
	struct timespec begints, endts;
	mkdir("rogue_dir");
	clock_gettime(CLOCK_MONOTONIC, &begints);
	int i;
	for (i=0; i<10000000;i++){
		chdir("rogue_dir");
		chdir("..");
	}
	clock_gettime(CLOCK_MONOTONIC, &endts);
	rmdir("rogue_dir");
}
