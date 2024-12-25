#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

const char* banner = 
"\n\t  ________  ________   _______   \n"
"\t /\"       )|\"      \"\\ |   _  \"\\  \n"
"\t(:   \\___/ (.  ___  :)(. |_)  :) \n"
"\t \\___  \\   |: \\   ) |||:     \\/  \n"
"\t  __/  \\\\  (| (___\\ ||(|  _  \\\\  \n"
"\t /\" \\   :) |:       :)|: |_)  :) \n"
"\t(_______/  (________/ (_______/  \n\n";


#define DB_SIZE 6
char gift_db[DB_SIZE][0x20] = {
    "Gravis' Pwn Chall",
    "PS12",
    "ARM64 MultiThreading Flag",
    "Kiss from Nish",
    "RTX 5090",
    "1 Win on Valo (for Mika)"
}; 

unsigned long santas_pin = 0;
char is_santa = 0;
char one_gift_allowed = 1;


char login_error[] = "You are not Santa ! >:c \n";

void show_gift();
void change_gift();
void auth();

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    char choice[0x10];
    int atoiyed;
    puts(banner);
    printf("Welcome to SDB, Santa's Database Manager !\n(also it spells Salle de Bain)\n");
    printf("Made with <3 by Gravis ^^\n");
    
    srand(time(NULL)^getpid());
    santas_pin = rand();

    while (1) {
        printf("\nChoose what you want to do !\n1: See what gift we have for Xmas\n2: Change a gift (requires to be Santa)\n3: Leave :(\n");
        printf("Your choice : ");
        fgets(choice, sizeof(choice), stdin);
        atoiyed = atoi(choice);
        if (atoiyed==1) {
            auth();
            show_gift();
        } 
        else if (atoiyed==2) {
            auth();
            change_gift();
        }   
        else if (atoiyed==3) {
            printf("Goodbye ! ;)");
            return 0;
        }
        else {
            printf("Unrocognized choice !");
        }
        sleep(1);
    }

    
    return 0;
}

void auth() {
    char login[0x10] = {0};
    char pass[0x10] = {0};

    printf("Lemme see those credentials");
    printf("Login : ");
    fgets(login, sizeof(login), stdin);
    printf("Password : ");
    fgets(pass, sizeof(pass), stdin);

    if (strcmp(login, "Santa")==0 && *(int*)pass==santas_pin) {
        printf("Welcome Santa ! :)");
        is_santa=1;
    } else {
        puts(login);
        puts(login_error);
    }  
}

void show_gift() {
    char choice[0xc] = {0};
    int n_gift; 
    if (!is_santa) {
        //before xmas, you get to see only one gift !
        if (!one_gift_allowed) {
            printf("You already saw it naughty !");
            return;
        }
        else {
            one_gift_allowed = 0;
        }
    }
    printf("Oh you're curious which gifts we're considering for Xmas ?");
    printf("Do you want to keep some xmas magic and see a random gift, or choose which one to see ?\nAnswer R for random or C to choose : ");
    fgets(choice, sizeof(choice), stdin);
    if (choice[0]=='R') {
        printf("Random one, nice choice !");
        n_gift = rand()%DB_SIZE;
    }
    else if (choice[0]=='C') {
        printf("Gift number : ");
        scanf("%d", &n_gift);
        getchar();
        if (n_gift<0 || n_gift>=DB_SIZE) {
            printf("This gift doesn't even exist, go to naughty list");
            return;
        } 
    }

    printf("Here's the %u%s gift : %s\n", n_gift, n_gift==1? "st": n_gift==2? "nd": n_gift==3? "rd": "th", gift_db[n_gift]);
}

void change_gift() {
    if (!is_santa) {
        printf("You are not Santa, you can't change a gift !!!");
    }
    int n_gift;
    printf("Tell me, which gift entry do you want to modify ? ");
    scanf("%d", &n_gift);
    getchar();

    printf("Go for it !");
    fgets(gift_db[n_gift], sizeof(gift_db[0]), stdin);
}