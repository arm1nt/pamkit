#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define _STR_SIZE(x) (sizeof(char) * (strlen(x)+1))

char *prog_name;

struct pam_conv conv = { 
    misc_conv, //generic PAM conv implementation
    NULL
};

static void
usage(void)
{
    fprintf(stderr, "Usage: %s service_name [config_dir]\n", prog_name);
    exit(EXIT_FAILURE);
}

static void *
_do_malloc(size_t mem_req)
{
    void *ret;
    ret = malloc(mem_req);

    if (!ret) abort();

    return ret;
}

static void inline
_do_free(void *pointer)
{
    free(pointer);
    pointer = NULL;
}

/**
 * @brief Prints the content of the associated PAM config file, libpam will read the exact same content.
 * 
 * @param path path to the config file.
 */
static void
print_pam_config(const char *path)
{
    struct stat sb;
    char *buffer = NULL;
    FILE *config_file = NULL;
    int fd;

    if (stat(path, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        fprintf(stderr, "invalid file path\n");
        exit(EXIT_FAILURE);
    }

    config_file = fopen(path, "r");
    if (!config_file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    fd = fileno(config_file);

    buffer = (char *)_do_malloc(sb.st_size);

    if (read(fd, buffer, sb.st_size) == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "****************** START ********************");
    fprintf(stdout, "\n%s\n", buffer);
    fprintf(stdout, "******************* END *********************\n");
    
    _do_free(buffer);
    fclose(config_file);
}


int
main(int argc, char **argv)
{
    prog_name = argv[0];

    if (argc < 2) {
        usage();
    }

    #ifdef CUSTOM_DIR
    if (argc < 3) {
        fprintf(stderr, "error: dir_path is required!\n");
        exit(EXIT_FAILURE);
    }
    char *dir_path = strdup(argv[2]);
    #else
    char *dir_path = "/etc/pam.d";
    #endif

    char *service_name = strdup(argv[1]);
    char *config_file_path = (char *)_do_malloc(_STR_SIZE(dir_path) + _STR_SIZE(service_name));

    strcat(config_file_path, dir_path);
    strcat(config_file_path, "/");
    strcat(config_file_path, service_name);

    printf("config file path: %s\n", config_file_path);
    printf("dir path: %s\n", dir_path);

    print_pam_config(config_file_path);

    pam_handle_t *pamh;
    int retval;
    const char *user = "armin";

    retval = pam_start_confdir(service_name, user, &conv, dir_path, &pamh);

    if (pamh == NULL || retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_start_confdir failed (ret val: %d)\n", retval);
        exit(EXIT_FAILURE);
    }
    
    retval = pam_authenticate(pamh, 0);

    if (retval == PAM_SUCCESS) {
        fprintf(stdout, "authentication was sucessful\n");
    } else {
        fprintf(stderr, "unable to authenticate (ret val: %d)\n", retval);
    }

    pam_end(pamh, retval);


    _do_free(config_file_path);
    _do_free(service_name);
    #ifdef CUSTOM_DIR
    _do_free(dir_path);
    #endif

    return retval;
}
