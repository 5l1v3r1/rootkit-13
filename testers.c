#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void write_test() {
	write(1, "hello1\n", 7);
        write(8, "hello2\n", 7);
        write(1, "hello3\n", 7);
	write(8, "1337KODEhello4\n", 14);
	write(8, "hello5\n", 7);
	write(1, "hello6\n", 7);
	write(8, "hello7\n", 7);
	write(1, "hello8\n", 7);
}

void read_test() {
	int pipefd[2];
        pipe(pipefd);
        pid_t cpid = fork();
        if(cpid==0) {
                //child, reading
                close(pipefd[1]);
                dup2(pipefd[0],8);
                char buf[4];
                read(8, buf, 4);        
        } else {
                //partent, writer
                close(pipefd[0]);
                write(pipefd[1],"AAAA",4);
        }
}

int main (int argc, char* argv[]) {
	if(argc < 2) {
		write(1, "Please enter test num.\n", 23);
		return 0;
	}

	char* endptr;
	long test = strtol(argv[1], &endptr, 10);

	switch(test) {
		case 1:
			write_test();
			break;
		case 2:
			read_test();
			break;
		default:
			break;
	}
		
	return 0;
}
