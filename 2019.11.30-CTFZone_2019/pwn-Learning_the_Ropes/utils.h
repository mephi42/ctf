#ifndef UTILS_H
#define UTILS_H

#include <errno.h>   // for errno
#include <stdarg.h>  // for va_end, va_list, va_start
#include <stdio.h>   // for size_t, NULL, vfprintf, stderr
#include <stdlib.h>  // for exit, EXIT_FAILURE
#include <string.h>  // for memchr, strerror, memmove
#include <unistd.h>  // for read, write, ssize_t

/* Keep error handling as primitive as possible */
__attribute__((noreturn))
__attribute__((format(printf, 1, 2)))
static void _die(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(EXIT_FAILURE);
}
#define die(fmt, ...) _die(fmt "\n", ##__VA_ARGS__)
#define die_errno(fmt, ...) do { \
	int err = errno; \
\
	_die(fmt ": %s\n", ##__VA_ARGS__, strerror(err)); \
} while (0)

__attribute__((unused))
static void read_n(int fd, char *buf, size_t count, const char *desc)
{
	ssize_t n_read;
	size_t total = 0;

	while (total < count) {
		n_read = read(fd, buf + total, count - total);
		if (n_read == -1)
			die_errno("Could not read from %s", desc);
		if (n_read == 0)
			die("Unexpected EOF while reading from %s", desc);
		total += n_read;
	}
}

static void write_n(int fd, const char *buf, size_t count)
{
	ssize_t n_written;
	size_t total = 0;

	while (total < count) {
		n_written = write(fd, buf + total, count - total);
		if (n_written == -1)
			die_errno("Could not write");
		total += n_written;
	}
}

static size_t read_until(int fd, char *buf, size_t count, int needle, char **pos, const char *desc)
{
	size_t total = 0;
	ssize_t n_read;

	while (total < count) {
		n_read = read(fd, buf + total, count - total);
		if (n_read == -1)
			die_errno("Could not read from %s", desc);
		if (n_read == 0)
			break;
		total += n_read;
		if ((*pos = memchr(buf + total - n_read, needle, n_read)))
			return n_read;
	}
	die("Could not find a separator in %s", desc);
}

struct line_buf {
	char *buf, *current, *newline, *next, *end;
};

static void line_buf_init(struct line_buf *lb, char *buf, size_t count)
{
	lb->buf = buf;
	lb->current = buf;
	lb->newline = NULL;
	lb->next = NULL;
	lb->end = buf + count;
}

static void line_buf_read(int fd, struct line_buf *lb, const char *desc)
{
	size_t n_read;

	lb->newline = memchr(lb->buf, '\n', lb->current - lb->buf);
	if (lb->newline == NULL) {
		n_read = read_until(fd, lb->current, lb->end - lb->current, '\n', &lb->newline, desc);
		lb->next = lb->current + n_read;
	} else {
		lb->next = lb->current;
	}
}

static void line_buf_read_stdin(struct line_buf *lb)
{
	line_buf_read(STDIN_FILENO, lb, "user input");
}

static void line_buf_next(struct line_buf *lb)
{
	size_t n_remaining = lb->next - lb->newline - 1;

	memmove(lb->buf, lb->newline + 1, n_remaining);
	lb->current = lb->buf + n_remaining;
	lb->newline = NULL;
	lb->next = NULL;
}

static const char CLEAR_HOME[] = "\033[2J\033[H";

#endif
