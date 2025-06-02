#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Global variables to make addresses predictable
char global_buffer[64] = "Welcome to the format string challenge!";
int secret_value = 0xdeadbeef;

void print_banner() {
    printf("=== Format String Challenge ===\n");
    printf("Your goal is to:\n");
    printf("1. Leak the program's base address\n");
    printf("2. Leak libc's base address\n");
    printf("3. Calculate the address of RIP\n");
    printf("4. Leak the canary value\n\n");
}

void print_hint(int step) {
    switch(step) {
        case 1:
            printf("\nHint for step 1: Try using %%p to leak addresses from the stack\n");
            printf("The program's base address will be one of these values\n");
            break;
        case 2:
            printf("\nHint for step 2: Look for addresses that point to libc functions\n");
            printf("Try using %%p with different offsets\n");
            break;
        case 3:
            printf("\nHint for step 3: Once you have the program's base address,\n");
            printf("you can calculate RIP's address relative to it\n");
            break;
        case 4:
            printf("\nHint for step 4: The canary is stored in a global variable\n");
            printf("Try to find it using format string specifiers\n");
            break;
    }
}

int main()
{
    char input[64];
    int step = 1;
    
    setvbuf(stdout, NULL, _IONBF, 0);
    
    print_banner();
    
    while(1) {
        printf("\nEnter your format string (or 'quit' to exit): ");
        if (fgets(input, sizeof(input), stdin) == NULL) break;
        
        input[strcspn(input, "\n")] = 0;
        
        if (strcmp(input, "quit") == 0) break;
 
        printf(input);
        printf("\n");
        
        print_hint(step);
        step = (step % 4) + 1;
    }
    
    return 0;
}
