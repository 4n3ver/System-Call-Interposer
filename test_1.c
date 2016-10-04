#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sched.h>
#include <stdio.h>
void test_func(){
	int junk_int;
	wait4(getppid(),&junk_int,NULL,NULL);
}
int main(){
	mkdir("test_dir",777);
	chmod("test_dir",776);
	chdir("test_dir");
	chdir("..");
	char buf[10];
	struct stat buf2;
	int pipefd[]={0,1};
	int tmp=0;
	tmp=access("test_dir", F_OK);
	int wait_pid=clone(test_func,NULL,NULL);
	getpid();
	//gettid();
	syscall(SYS_gettid);
	int fd=open("test_file",O_RDWR);
	tmp=read(fd,buf,1);
	tmp=write(fd,"red",3);
	int fd2=dup(fd);
	tmp=dup2(fd,fd2);
	tmp=fcntl(fd,F_GETFD);
	tmp=lseek(fd,0,SEEK_SET);
	tmp=stat("test_dir/test_file",&buf2);
	tmp=fstat(fd,&buf2);
	tmp=lstat("test_dir/test_file",&buf2);
	mmap(0,0,PROT_READ,MAP_SHARED,fd,0);
	munmap(0,0);
	ioctl(fd,NULL);
	close(fd);

	pipe(pipefd);

	fd_set rfds;
	struct timeval tv;
	int retval;

	/* Watch stdin (fd 0) to see when it has input. */
	FD_ZERO(&rfds);
	FD_SET(0, &rfds);

	/* Wait up to five seconds. */
	tv.tv_sec = 0;
	tv.tv_usec = 5;

	retval=select(1,&rfds,NULL,NULL,&tv);

	fd=open("test_dir",O_RDONLY|O_DIRECTORY);
	syscall(SYS_getdents,fd,buf,10);

	rmdir("test_dir");

	

	tmp=brk(0);
	fork();
	//exit_group(0);
	syscall(SYS_exit_group);
	return 0;
}

