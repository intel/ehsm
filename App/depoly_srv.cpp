#include <stdio.h>
#include <Enclave_u.h>

void ocall_print_string(const char *str)
{
     printf("%s", str);
}


int main(int argc, char* argv[]) {
	printf("helloworld\n");
	return 0;
}

