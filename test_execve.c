#include <unistd.h>

int main(){
	char *red[]={"./test_1","test_1",NULL};
	execve("./test_1",red,red);
}
