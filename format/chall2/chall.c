#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sendfile.h>

#define BUF_SIZE 0x408

void init(char **argv, char **envp) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // Close all high file descriptors
    for(int fd = 3; fd <= 9999; fd++) close(fd);
    
    // Wipe command line arguments
    for(char** p = argv; *p; p++)
        memset(*p, 0, strlen(*p));
    
    // Wipe environment variables
    for(char** p = envp; *p; p++)
        memset(*p, 0, strlen(*p));
}

void win() {
    puts("Access granted! Here is your master password:");
    int fd = open("flag.txt", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open master password file");
        exit(1);
    }
    sendfile(STDOUT_FILENO, fd, 0, 0x400);
    exit(0);
}

void func() {
    char format[BUF_SIZE];
    int counter = 0;
    
    while(1) {
        memset(format, 0, BUF_SIZE);
        printf("Enter password query (type 'END' to exit): ");
        ssize_t bytes_read = read(STDIN_FILENO, format, BUF_SIZE-1);
        
        if (bytes_read <= 0) break;
        if (strstr(format, "END")) break;
        
        printf("Searching vault for: ");
        printf(format);
        puts("");
    }
}

int main(int argc, char** argv, char** envp) {
    init(argv, envp);
    
    puts("==========================================");
    printf("Welcome to SecureVault v1.0 - %s\n", argv[0]);
    puts("==========================================");
    puts("\nThis is a secure password vault system.");
    puts("You can query the vault for stored passwords.");
    puts("Type 'END' to exit the system.\n");

    func();
    puts("Vault session terminated. Goodbye!");
    return 0;
}