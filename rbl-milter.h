 /*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
    
    If you have any questions, please contact Jeremy Beker <gothmog@confusticate.com>
*/

#include <libmilter/mfapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <syslog.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#include <resolv.h>

#ifndef bool
#define bool char
#define TRUE 1
#define FALSE 0
#endif

#ifndef DEF_LOGFAC
#define DEF_LOGFAC LOG_LOCAL0
#endif
#ifndef DEF_LOGPRIO
#define DEF_LOGPRIO LOG_INFO
#endif

#define MAX_HOST_LEN 255

/* Global Structures */
struct rblHost
{
	char* rblSuffix;
	struct IPlist *mip;
	struct rblHost *next;
};

struct IPlist
{
	struct in_addr ipaddr;
	struct IPlist *next;
};

struct mlfiRBLInfo
{
  bool	isBL;
  struct rblHost	*conn;
  struct rblHost	*msg;
#ifdef HAVE___RES_NINIT
  res_state statp;
#endif
};

/* Global variables */
struct rblHost *head;
regex_t reg;
bool debug;

/* match IP address enclosed in []'s */
const char ipregex[] = "\\[(([0-9]){1,3}\\.){1,3}([0-9]){1,3}\\]";
static char AppIdent[] = "rbl-milter";

/* internal helper functions */
	/* regexp error handling from GNU libc info page */
char *get_regerror (int errcode, regex_t *compiled);

bool isRFC1918(const struct in_addr *addr);
int scanip (char **str);
int dnsblcheck(const struct mlfiRBLInfo *priv, const struct in_addr *addr, const char* dnsbl);
char *makeheader(const char *dnsbl, struct in_addr *ip);
struct IPlist *getips(char *header);
static void usage();
void logIP (const struct in_addr *addr);

	/* rblHost list manipulation functions */
struct rblHost *initRbl(const struct rblHost *master);
int addRbl(struct rblHost *rbl, struct in_addr *addr);
void freeRbl(struct rblHost *rbl);

/* libmilter callback functions */
sfsistat mlfi_hdr (SMFICTX *ctx, char *headerf, char *headerv);
sfsistat mlfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr);
sfsistat mlfi_eom(SMFICTX *ctx);
sfsistat mlfi_close(SMFICTX *ctx);
sfsistat mlfi_abort(SMFICTX *ctx);
sfsistat mlfi_envfrom(SMFICTX *ctx, char **argv);


struct smfiDesc smfilter =
{
    "rbl-filter", /* filter name */
    SMFI_VERSION,   /* version code -- do not change */
    SMFIF_ADDHDRS,  /* flags */
    mlfi_connect,   /* connection info filter */
    NULL,      /* SMTP HELO command filter */
    mlfi_envfrom,   /* envelope sender filter */
    NULL,   /* envelope recipient filter */
    mlfi_hdr,    /* header filter */
    NULL,       /* end of header */
    NULL,      /* body block filter */
    mlfi_eom,       /* end of message */
    mlfi_abort,     /* message aborted */
    mlfi_close,     /* connection cleanup */
};
