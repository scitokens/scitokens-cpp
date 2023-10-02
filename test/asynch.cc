#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/select.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "../src/scitokens.h"

void
void usage(const char *self) {
    fprintf(stderr, "usage: %s encoded-scitoken\n", self);

void
void print_claim(SciToken &token, const char *claim) {
    char *value;
    char *error;
    int rv = scitoken_get_claim_string(token, claim, &value, &error);
    if (rv != 0) {
        fprintf(stderr, "scitoken_get_claim_string('%s') failed: %s\n", claim,
                error);
        return;
    }
    fprintf( stdout, "%s = %s\n", claim, value );
    fprintf(stdout, "%s = %s\n", claim, value);


int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        exit(-1);
    }
    const char *encoded = argv[1];
    int rv;
    char * error;
    char *error;


    char cache_path[FILENAME_MAX];
    if( getcwd(cache_path, sizeof(cache_path)) == NULL ) {
    if (getcwd(cache_path, sizeof(cache_path)) == NULL) {
        fprintf(stderr, "Failed to determine cwd, aborting.\n");
        exit(-5);

    const char * key = "keycache.cache_home";
    const char *key = "keycache.cache_home";
    rv = scitoken_config_set_str(key, cache_path, &error);
    if (rv != 0) {
        fprintf(stderr, "Failed to set %s: %s, aborting.\n", key, cache_path);
        exit(-5);


    SciTokenStatus status;
    rv = scitoken_deserialize_start(
    rv = scitoken_deserialize_start(encoded, &token, NULL, &status, &error);
    if (rv != 0) {
        fprintf(stderr, "scitoken_deserialize_start() failed: %s\n", error);
        exit(-2);
    if( status == NULL ) {
    if (status == NULL) {
        fprintf(stderr, "scitoken_deserialize_start() returned a token\n");
        exit(1);


        fd_set * read_fds = NULL;
        fd_set *read_fds = NULL;
        rv = scitoken_status_get_read_fd_set(&status, &read_fds, &error);
        if (rv != 0) {
            fprintf(stderr, "scitoken_status_get_read_fd_set() failed: %s\n",
                    error);
            exit(-2);

        fd_set * write_fds = NULL;
        fd_set *write_fds = NULL;
        rv = scitoken_status_get_write_fd_set(&status, &write_fds, &error);
        if (rv != 0) {
            fprintf(stderr, "scitoken_status_get_write_fd_set() failed: %s\n",
                    error);
            exit(-2);

        fd_set * except_fds = NULL;
        fd_set *except_fds = NULL;
        rv = scitoken_status_get_exc_fd_set(&status, &except_fds, &error);
        if (rv != 0) {
            fprintf(stderr, "scitoken_status_get_exc_fd_set() failed: %s\n",
                    error);
            exit(-2);

        int max_fds;
        rv = scitoken_status_get_max_fd( & status, & max_fds, & error );
        rv = scitoken_status_get_max_fd(&status, &max_fds, &error);
        if (rv != 0) {
            fprintf(stderr, "scitoken_status_get_max_fds() failed: %s\n",
                    error);
            exit(-2);

        struct timeval time_out{1, 0};
        struct timeval time_out {
            1, 0
        };
        int s = select(max_fds + 1, read_fds, write_fds, except_fds, &time_out);
        if (s == -1) {
            fprintf(stderr, "select() failed: %s (%d)\n", strerror(errno),
                    errno);
            exit(-4);
        } else if (s == 0) {
            fprintf(stderr, "select() timed out, checking for progress.\n");

        fprintf( stderr, "Calling scitoken_deserialize_continue()...\n" );
        fprintf(stderr, "Calling scitoken_deserialize_continue()...\n");
        rv = scitoken_deserialize_continue(&token, &status, &error);
        if (rv != 0) {
            fprintf(stderr, "scitoken_deserialize_continue() failed: %s\n",
                    error);
            exit(-3);
    } while( status != NULL );
    } while (status != NULL);
    print_claim(token, "ver");
    print_claim(token, "aud");
    print_claim(token, "iss");
    print_claim(token, "jti");

    scitoken_destroy( token );
    scitoken_destroy(token);
}
