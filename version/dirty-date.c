/*
 * Written by Tony Finch <dot@dotat.at> in Cambridge.
 *
 * Permission is hereby granted to use, copy, modify, and/or
 * distribute this software for any purpose with or without fee.
 *
 * This software is provided 'as is', without warranty of any kind.
 * In no event shall the authors be liable for any damages arising
 * from the use of this software.
 *
 * SPDX-License-Identifier: 0BSD OR MIT-0
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <err.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	struct stat st;
	time_t t = 0;
	char buf[] = "YYYY-MM-DD HH:MM:SS +0000\n";

	if(argc < 2)
		errx(1, "no arguments");

	for(++argv; *argv; ++argv)
		if(lstat(*argv, &st) < 0)
			err(1, "stat %s", *argv);
		else if(t < st.st_mtime)
			t = st.st_mtime;

	strftime(buf, sizeof(buf), "%F %T %z\n", localtime(&t));
	write(1, buf, sizeof(buf)-1);
	return(0);
}
