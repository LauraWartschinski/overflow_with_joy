#include "string.h"
#include "stdio.h"
#include "time.h"
#include "stdlib.h"

void jackpot()
{
  printf("\n\n$$$ You hit the jackpot!!! $$$\nAll money will be transferred to your account immediately.\n\n");
  return;
}

void play()
{
  srand(time(0)); 
  int random = rand()%1000;
  int number = rand()/10000000;
  printf("\n\n======PLAYING THE GAME=====\n");
  printf("The lucky number today is: %d\n", random);
  printf("You rolled: %d.\n", number);
  if (number == random){
    jackpot();
  } else {
    printf("Sadly, this means you didn't win.\n");
  }
  return;
}

int main()
{
	void (*functionptr)();
  functionptr = &play;
  char name[8];   // first name of the player
  printf("Welcome to this game of luck! What is your fist name:\n");
  scanf("%s",name);
  functionptr();
  printf("Game finished.\n");
	return 0;  
}