router: zad.o
	gcc -g -pthread -o router -Wall -Wextra -std=c17 zad.o

zad.o:
	gcc -c zad.c

clean:
	rm ./zad.o

disclean:
	rm ./zad.o ./router
