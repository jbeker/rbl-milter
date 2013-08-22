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

#include "rbl-milter.h"

/* regexp error handling from GNU libc info page */
char *get_regerror(int errcode, regex_t * compiled)
{
	char *buffer;
	size_t length = regerror(errcode, compiled, NULL, 0);

	if (!(buffer = (char *) malloc(length)))
		return NULL;
	(void) regerror(errcode, compiled, buffer, length);
	return buffer;
}


/* scanip: search string for IP address enclosed in []'s
 * takes: address of pointer to string
 * returns: len == length of IP address found
 * 			or 0 if no match
 * pointer to string is set to point at beginning of IP addr
 */
int scanip(char **str)
{

	int ret;
	size_t len;
	char *errbuf;
	regmatch_t *regm;

	regm = (regmatch_t *) calloc(reg.re_nsub, sizeof(regmatch_t));
	if ( regm == NULL ) {
		return 0;
	}

	ret = regexec(&reg, *str, reg.re_nsub, regm, 0);
	if (ret != 0 && ret != REG_NOMATCH) {
		errbuf = get_regerror(ret, &reg);
		if (debug) {
			fprintf(stderr, "reg: %s\n", errbuf);
		}
		free(errbuf);
		free(regm);
		return 0;
	} else if (ret == REG_NOMATCH) {
		free(regm);
		return 0;
	} else {
		len = regm->rm_eo - regm->rm_so;
		/* point *str past leading angle bracket */
		*str = (*str + regm->rm_so + 1);
		free(regm);
		/* return length minus length of []'s */
		return len - 2;
	}
}

char *
makeheader(const char *dnsbl, struct in_addr *ip) {

	const char hdrb[] = "Warning: (";
	const char hdrm[] = ") listed as open relay by ";
	const char hdre[] = " - checked with rbl-milter";	
	char *header, *ipa;
	int headerlen;

	ipa = inet_ntoa(*ip);

	headerlen = (sizeof(hdrb) + sizeof(hdre) + sizeof(hdrm) +
		strlen(dnsbl)) + strlen(ipa) + 1;
	
	header = (char *) calloc(headerlen, sizeof(char));
	
	if (header == NULL) {
		return NULL;
	}
	
	sprintf(header, "%s%s%s%s%s", hdrb, ipa, hdrm, dnsbl, hdre);

	return header;
}

/* create a new rblHost initialised with the list of rbl's from master
 * returns pointer to rblHost or NULL on failure
 * returned rblHost is not guaranteed to be complete
 */
struct rblHost * 
initRbl(const struct rblHost *master) {

	struct rblHost *top, *next, *this;

	top = (struct rblHost *) calloc(1,sizeof(struct rblHost));

	if (top == NULL)
		return top;
	
	memcpy(top, master, sizeof(struct rblHost));

	this = top;

	/* copy the linked list that top points through to to list of top itself
	 */ 
	while (this->next) {
		next = (struct rblHost *) malloc(sizeof(struct rblHost));
		if (next) {
			memcpy(next, this->next, sizeof(struct rblHost));
			this = this->next = next;
		}
	}

	return top;
}

/* add an IP address to the specified rblHost */
int
addRbl(struct rblHost *rbl, struct in_addr *addr) {

	struct IPlist *ip;

	ip = calloc(1,sizeof(struct IPlist));

	if (!ip) {
		return 1;
	}

	memcpy(&ip->ipaddr, addr, sizeof(ip->ipaddr));

	if (!rbl->mip) {
		rbl->mip = ip;
	} else {
		ip->next = rbl->mip->next;
		rbl->mip = ip;
	}
		
	if (debug) {
		fprintf(stderr,"addRbl: added %s to %s\n", 
			inet_ntoa(rbl->mip->ipaddr),rbl->rblSuffix);
	}

	return 0;
}

void
freeRbl(struct rblHost *rbl) {

	struct rblHost *t;
	struct IPlist *i;

	while (rbl) {
		while(rbl->mip) {
			i = rbl->mip;
			rbl->mip = rbl->mip->next;
			free(i);
		}
		t = rbl;
		rbl = rbl->next;
		free(t);
	}
}

/* checks an address against specified blacklist
 * returns lookup response
 */
int
dnsblcheck(const struct mlfiRBLInfo *priv, const struct in_addr *addr, const char *dnsbl)
{
	char *lookup; 
	unsigned char *answer;
	int res_len = -1, lookuplen;


	if (isRFC1918(addr))
	{
		return res_len;
	}

	lookuplen = (strlen(dnsbl) + 20);

	lookup = (char *) calloc(1,lookuplen);
	if (lookup == NULL) {
		return res_len;
	}

	answer = (unsigned char *) calloc(1, MAX_HOST_LEN);
	if (answer == NULL) {
		free(lookup);
		return res_len;
	}

#ifdef WORDS_BIGENDIAN
	sprintf(lookup, "%d.%d.%d.%d.%s",
		(addr->s_addr) & 0xff,
		(addr->s_addr >> 8) & 0xff,
		(addr->s_addr >> 16) & 0xff, 
		(addr->s_addr >> 24) & 0xff, dnsbl);
#else
	sprintf(lookup, "%d.%d.%d.%d.%s",
		(addr->s_addr >> 24) & 0xff,
		(addr->s_addr >> 16) & 0xff,
		(addr->s_addr >> 8) & 0xff, 
		(addr->s_addr) & 0xff, dnsbl);
#endif

	if (debug) {
		fprintf(stderr, "checking %s as %s\n", dnsbl, lookup);
	}
#ifdef HAVE___RES_NINIT
	res_len =
	    res_nquery(priv->statp, lookup, C_IN, T_A, answer,
		       MAX_HOST_LEN);
#else
	res_len = res_query(lookup, C_IN, T_A, answer, MAX_HOST_LEN);
#endif

	if (debug) {
		fprintf(stderr, "got len %d for %s\n", res_len, lookup);
	}


	if(res_len >0)
	{
		logIP(addr);
	}

	free(lookup);
	free(answer);

	return res_len;
}

void logIP (const struct in_addr *addr)
{
	char *host;
	host = (char *) calloc(1,20);
	
#ifdef WORDS_BIGENDIAN
	sprintf(host, "%d.%d.%d.%d",
		(addr->s_addr >> 24) & 0xff,
		(addr->s_addr >> 16) & 0xff,
		(addr->s_addr >> 8) & 0xff, 
		(addr->s_addr) & 0xff);
#else
	sprintf(host, "%d.%d.%d.%d",
		(addr->s_addr) & 0xff,
		(addr->s_addr >> 8) & 0xff,
		(addr->s_addr >> 16) & 0xff, 
		(addr->s_addr >> 24) & 0xff);
#endif
	
	syslog(LOG_INFO,"RBL entry found for %s",host);
	
	free(host);
}

bool isRFC1918(const struct in_addr *addr) 
{

	bool ret = FALSE;

#ifdef WORDS_BIGENDIAN
	
	switch ((addr->s_addr >> 24) & 0xff)
	{
		case 10:
			ret = TRUE;
			break;
			
		case 172:
			if ( ((addr->s_addr >> 16) & 0xff) >= 16 && ((addr->s_addr >> 16) & 0xff) <= 31) 
				ret = TRUE;
			break;
	
		case 192:
			if (((addr->s_addr >> 16) & 0xff) == 168)
				ret = TRUE;
			break;
	}
#else
	switch ((addr->s_addr) & 0xff)
	{
		case 10:
			ret = TRUE;
			break;
			
		case 172:
			if ( ((addr->s_addr >> 8) & 0xff) >= 16 && ((addr->s_addr >> 8) & 0xff) <= 31) 
				ret = TRUE;
			break;
	
		case 192:
			if (((addr->s_addr >> 8) & 0xff) == 168)
				ret = TRUE;
			break;
	}
#endif

	if (debug) {
			fprintf(stderr, "isRFC1918: %d\n",ret);
	}

	return ret;
}

struct IPlist *
getips(char *header) {

	char *ipstr;
	struct in_addr ipaddr;
	struct IPlist *iplist = NULL, *newip;
	int len;

	while ( (len=scanip(&header)) > 0) {

		ipstr = (char *) calloc(len + 1, sizeof(char));
		if (ipstr == NULL) {
			return iplist;
		}
	
		snprintf(ipstr, len + 1, "%s", header);
		if (!inet_aton(ipstr, &ipaddr)) {
			free(ipstr);
			continue;
		}

		newip = calloc(1, sizeof(struct IPlist));
		if (!newip) {
			free(ipstr);
			return iplist;
		}
		
		memcpy(&newip->ipaddr, &ipaddr, sizeof(struct in_addr));
		if (iplist) {
			newip->next = iplist->next;
		}
		iplist = newip;
		
		free(ipstr);
		header += len;
	}	

	return iplist;
}

sfsistat mlfi_hdr(SMFICTX * ctx, char *headerf, char *headerv)
{
	struct rblHost *t;
	struct IPlist *ipl, *i;
	struct mlfiRBLInfo *priv;

	if (strcmp(headerf, "Received") != 0) {
		return SMFIS_CONTINUE;
	}

	priv = (struct mlfiRBLInfo *) smfi_getpriv(ctx);

	t = priv->msg;

	i = ipl = getips(headerv);

	while (i) {
		while (t) {
			if (dnsblcheck(priv, &i->ipaddr, t->rblSuffix) > 0) {
				priv->isBL = TRUE;
				addRbl(t, &i->ipaddr);
			}
			t = t->next;
		}
		i = i->next;
	}

	while (ipl) {
		i = ipl;
		ipl = ipl->next;
		free(i);
	}		

	return SMFIS_CONTINUE;
}


sfsistat mlfi_connect(SMFICTX * ctx, char *hostname, _SOCK_ADDR * hostaddr)
{
	struct mlfiRBLInfo *priv;
	struct sockaddr_in *host;
	struct rblHost *t;

	priv = (struct mlfiRBLInfo *) malloc(sizeof *priv);

	if (priv == NULL) {
		return SMFIS_CONTINUE;
	}
	memset(priv, 0, sizeof(*priv));

	t = initRbl(head);

	if (t == NULL) {
		return SMFIS_CONTINUE;
	}

	priv->conn = t;

	priv->isBL = FALSE;

#ifdef HAVE___RES_NINIT
	priv->statp = malloc(sizeof *(priv->statp));
	if (priv->statp == NULL) {
		return SMFIS_TEMPFAIL;
	}
#endif

	smfi_setpriv(ctx, priv);

	host = (struct sockaddr_in *) hostaddr;

#ifdef HAVE___RES_NINIT
	res_ninit(priv->statp);
#else
	res_init();
#endif

	if (!host) {
		return SMFIS_CONTINUE;
	}

	while (t) {
		if (dnsblcheck(priv,&host->sin_addr, t->rblSuffix) > 0) {
			// Found a match, RBL it.
			addRbl(t, &host->sin_addr);
		}
		t = t->next;
	}
	return SMFIS_CONTINUE;
}

sfsistat mlfi_eom(SMFICTX * ctx)
{
	struct mlfiRBLInfo *priv;
	struct rblHost *t;
	struct IPlist *ip;

	priv = (struct mlfiRBLInfo *) smfi_getpriv(ctx);

	if (!priv) {
		/* should this be accept or tmp_fail? */
		return SMFIS_ACCEPT;
	}

	if (!priv->isBL) {
		freeRbl(priv->msg);
		priv->msg = NULL;
		smfi_setpriv(ctx, priv);
		return SMFIS_ACCEPT;
	}

	t = priv->msg;

	while (t != NULL) {
		ip = t->mip;
		if (debug) {
			fprintf(stderr, "eom: considering matches on %s\n", t->rblSuffix);
			fprintf(stderr, "eom: ip is %p\n", ip);
		}
		while (ip != NULL) {
			char *header;
	
			header = makeheader(t->rblSuffix,&ip->ipaddr);

			if (debug) {
				fprintf(stderr, "Adding header %s\n",header);
			}

			smfi_addheader(ctx, "X-RBL-Warning", header);

			free(header);
			ip = ip->next;
		}
		t = t->next;
	}

	t = priv->conn;

	while (t) {
		ip = t->mip;
		while (ip) {
			char *header;
	
			header = makeheader(t->rblSuffix,&ip->ipaddr);

			if (debug) {
				fprintf(stderr, "Adding header %s\n",header);
			}

			smfi_addheader(ctx, "X-RBL-Warning", header);

			free(header);
			ip = ip->next;
		}
		t = t->next;
	}

	freeRbl(priv->msg);
	priv->msg = NULL;
	smfi_setpriv(ctx, priv);

	return SMFIS_ACCEPT;
}

sfsistat 
mlfi_envfrom(SMFICTX *ctx, char **argv) {
	struct mlfiRBLInfo *priv;
	priv = (struct mlfiRBLInfo *) smfi_getpriv(ctx);

	if (priv != NULL) {
		struct rblHost *t;

		t = initRbl(head);
		priv->msg = t;
		smfi_setpriv(ctx, priv);
	}

	return SMFIS_CONTINUE;

}
	

sfsistat mlfi_close(SMFICTX * ctx)
{
	struct mlfiRBLInfo *priv;
	priv = (struct mlfiRBLInfo *) smfi_getpriv(ctx);

	if (priv != NULL) {
		struct rblHost *t;

		t = priv->conn;
		freeRbl(t);
	
#ifdef HAVE___RES_NINIT
		if (priv->statp != NULL) {
			free(priv->statp);
		}
#endif
		free(priv);
		smfi_setpriv(ctx, NULL);
	}

	if (debug) {
		fprintf(stderr, "Done\n");
	}

	return SMFIS_CONTINUE;
}

sfsistat mlfi_abort(SMFICTX * ctx)
{
	struct mlfiRBLInfo *priv;
	struct rblHost *t;

	priv = (struct mlfiRBLInfo *) smfi_getpriv(ctx);

	if (priv != NULL) {
		t = priv->msg;
		freeRbl(t);
	}

	return SMFIS_CONTINUE;
}

static void usage()
{
	fprintf(stderr,
		"Usage: rbl-milter [-f] [-t timeout] -p socket-addr -d hostname_suffix [-d ...]\n");
	fprintf(stderr, "\t-f\tRun in forground\n");
	fprintf(stderr, "\t-p\tSocket Address for Sendmail connection\n");
	fprintf(stderr, "\t-t\tTimeout\n");
	fprintf(stderr, "\t-d\tRBL DNS entries (may have multiple)\n");
	fprintf(stderr, "\t-r\tCheck IP addresses in Received headers\n");
	fprintf(stderr, "\t-l\tLog IP addresses found to syslog\n");
}

int main(int argc, char *argv[])
{
	int retval = 0;
	char c;
	const char *args = "d:p:t:l::hfr";
	extern char *optarg;
	char *socket = NULL, *regerrbuf;
	pid_t child;
	struct rblHost *temp;
	bool bg = TRUE;
	bool syslog = FALSE;
	bool recvhdrs = FALSE;

	head = NULL;
	debug = FALSE;

	/* Process command line options */
	while ((c = getopt(argc, argv, args)) != (char) EOF) {
		switch (c) {
		case 'd':
			if (optarg == NULL || *optarg == '\0') {

				(void) fprintf(stderr,
					       "Illegal host suffix: %s\n",
					       optarg); exit(EX_USAGE);
			}

			temp = head;

			head = malloc(sizeof(*head));
			if (head == NULL) {
				return EX_UNAVAILABLE;
			}
			memset(head,0,sizeof(*head));

			head->next = temp;

			head->rblSuffix = malloc(strlen(optarg) + 1);
			if (head->rblSuffix == NULL) {
				return EX_UNAVAILABLE;
			}
			memset(head->rblSuffix, 0, strlen(optarg) + 1);

			memcpy(head->rblSuffix, optarg, strlen(optarg));

			break;

		case 'p':
			if (optarg == NULL || *optarg == '\0') {

				(void) fprintf(stderr,
					       "Illegal conn: %s\n",
					       optarg);
				exit(EX_USAGE);
			}

			socket = malloc(strlen(optarg) + 1);
			memcpy(socket, optarg, strlen(optarg) + 1);

			/* 
			   ** If we're using a local socket, make sure it doesn't
			   ** already exist.
			 */
			if (strncmp(optarg, "unix:", 5) == 0) {
				unlink(optarg + 5);
			} else if (strncmp(optarg, "local:", 6) == 0) {
				unlink(optarg + 6);
			}
			break;

		case 't':
			if (optarg == NULL || *optarg == '\0') {

				(void) fprintf(stderr,
					       "Illegal timeout: %s\n",
					       optarg);
				exit(EX_USAGE);
			}
			if (smfi_settimeout(atoi(optarg)) == MI_FAILURE) {
				(void) fputs("smfi_settimeout failed", stderr);
				exit(EX_SOFTWARE);
			}
			break;

		case 'f':
			bg = FALSE;
			debug = TRUE;
			break;

		case 'l':
			syslog = TRUE;
			break;

		case 'r':
			recvhdrs = TRUE;
			break;

		case 'h':
		default:
			usage();
			exit(0);
		}
	}

	// make sure they gave us at least one server.

	if (head == NULL) {
		usage();
		exit(EX_USAGE);
	}

	if (recvhdrs != TRUE) {
		smfilter.xxfi_header = NULL;
	}

	retval = regcomp(&reg, ipregex, REG_EXTENDED);
	if (retval != 0) {
		regerrbuf = get_regerror(retval, &reg);
		if (debug) {
			fprintf(stderr, "reg: %s\n", regerrbuf);
		}
		free(regerrbuf);
		return EX_SOFTWARE;
	}
	retval = 0;


	if (bg) {
		child = fork();
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	} else {
		child = 0;
	}

	if (child == -1) {
		fprintf(stderr, "Error forking\n");
	} else if (child == 0) {
		struct rblHost *t, *x;

		if (smfi_register(smfilter) == MI_FAILURE) {
			fprintf(stderr, "smfi_register failed\n");
			exit(EX_UNAVAILABLE);
		}

		if (smfi_setconn(socket) == MI_FAILURE) {
			(void) fputs("smfi_setconn failed", stderr);
			exit(EX_SOFTWARE);
		}
		
		if (syslog)
		{
			openlog(AppIdent,LOG_PID|LOG_NDELAY,LOG_MAIL);
		}

		retval = smfi_main();


		if (syslog)
		{
			closelog();
		}
		
		// clean up mem
		t = head;

		while (t) {
			x = t;
			t = t->next;
			free(x->rblSuffix);
			free(x);
		}
		free(socket);

		return retval;
	} else {
		if (debug) {
			fprintf(stderr, "child at %d\n", (int)child);
		}
	}

	return retval;
}
