/*
   POSIX getopt for Windows

   AT&T Public License

   Code given out at the 1985 UNIFORUM conference in Dallas.
 */


extern int opterr;
extern int optind;
extern int optopt;
extern char *optarg;
extern int getopt(int argc, char **argv, char *opts);