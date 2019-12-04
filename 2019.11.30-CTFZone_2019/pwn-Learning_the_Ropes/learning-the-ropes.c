#include <stdio.h>      // for snprintf, size_t
#include <stdlib.h>     // for exit, atoi, EXIT_FAILURE
#include <string.h>     // for strcmp
#include <sys/param.h>  // for MIN
#include <unistd.h>     // for STDOUT_FILENO, STDIN_FILENO
#include "utils.h"      // for write_n, line_buf, line_buf_next, line_buf_re...

static const char ROPES[] = {
#include "learning-the-ropes.h"
};

static const char QUESTION1[] = "Greetings! What's your name?> ";
static const char QUESTION3[] = "Oh yeah? How many bytes can you ROP?> ";
static const char QUESTION4[] = "You'll have to give me 110%!> ";

int main(void)
{
	char in_buf[128], out_buf[128];
	struct line_buf lb;
	size_t i;

	line_buf_init(&lb, in_buf, sizeof(in_buf));
	write_n(STDOUT_FILENO, CLEAR_HOME, sizeof(CLEAR_HOME) - 1);
	write_n(STDOUT_FILENO, ROPES, sizeof(ROPES));
	write_n(STDOUT_FILENO, QUESTION1, sizeof(QUESTION1) - 1);
	line_buf_read_stdin(&lb);
	*lb.newline = 0;
	/* This needs to be silly and obvious */
	i = MIN(snprintf(out_buf, sizeof(out_buf), lb.buf), sizeof(out_buf));
	i += MIN(snprintf(out_buf + i, sizeof(out_buf) - i,
			  ", you coming here means you think you are a pwner.\n"
			  "But do you even ROP?> "),
		 sizeof(out_buf) - i);
	line_buf_next(&lb);
        write_n(STDOUT_FILENO, out_buf, i);
        line_buf_read_stdin(&lb);
        *lb.newline = 0;
        if (strcmp(lb.buf, "HELL YEAH") != 0)
                exit(EXIT_FAILURE);
        line_buf_next(&lb);
        write_n(STDOUT_FILENO, QUESTION3, sizeof(QUESTION3) - 1);
        line_buf_read_stdin(&lb);
        *lb.newline = 0;
        i = atoi(lb.buf);
        i += (i + 9) / 10;
        line_buf_next(&lb);
        write_n(STDOUT_FILENO, QUESTION4, sizeof(QUESTION4) - 1);
        read_n(STDIN_FILENO, lb.current, i - (lb.current - lb.buf), "user input");
        return EXIT_FAILURE;
}
