/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/
#include <unistd.h>
#include <stdlib.h>
#include <wordexp.h>
#include <stdio.h>
#include <errno.h>

#define USAGE \
"Usage: %1$s [OPTIONS] COMMAND\n" \
"\n" \
"With OPTIONS:\n" \
"    -c      -- Read commands from the command_string operand (MANDATORY).\n" \
"    -h      -- Print this message.\n" \
"    -n      -- Read commands but do not execute them. \n" \
"               This is useful for checking the syntax of shell scripts.\n" \
"\n" \
"Where:\n" \
"    COMMAND -- Shell command string.\n"

static
void
show_usage(void)
{
	fprintf(stderr, USAGE, program_invocation_short_name);
}

int
main(int argc, char * const argv[])
{
	int noexec = 0;
	const char *command = NULL;
	int opt;
	int ret;
	wordexp_t p;
	char **cmd;

	while ((opt = getopt(argc, argv, "hnc:")) != -1) {
		switch (opt) {
		case 'n':
			noexec = 1;
			break;
		case 'c':
			if (command) {
				fprintf(stderr, "Command already set\n");
				show_usage();
				return EXIT_FAILURE;
			}
			command = optarg;
			break;
		case 'h':
			show_usage();
			return EXIT_SUCCESS;
		default:
			fprintf(stderr, "Unknown option '%c'\n", opt);
			show_usage();
			return EXIT_FAILURE;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "Invalid arguments\n");
		show_usage();
		return EXIT_FAILURE;
	}

	if (!command) {
		fprintf(stderr, "Command not set\n");
		show_usage();
		return EXIT_FAILURE;
	}


	ret = wordexp(command, &p, 0);
	switch (ret) {
	case WRDE_BADCHAR:
		fprintf(stderr, "Bad char found\n");
		show_usage();
		return EXIT_FAILURE;
	case WRDE_SYNTAX:
		fprintf(stderr, "Syntax error\n");
		show_usage();
		return EXIT_FAILURE;
	case WRDE_NOSPACE:
		fprintf(stderr, "Out of memory\n");
		show_usage();
		return EXIT_FAILURE;
	case 0:
		break;
	}

	if (noexec) {
		wordfree(&p);
		return EXIT_SUCCESS;
	}

	cmd = p.we_wordv;
	execvp(cmd[0], cmd);
	wordfree(&p);
	return -errno;
}
