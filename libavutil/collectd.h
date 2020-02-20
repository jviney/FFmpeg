#include "collectd/client.h"

typedef struct AVCollectdClient {
    void *ctx; // Used for logging

    char address[1024]; // Server

    lcc_connection_t *conn;
    int64_t connect_attempted_at;
    int64_t reconnect_delay_us;
} AVCollectdClient;

/*
 * Allocate a new collectd client. Does not attempt to connect to the server.
 * Returns NULL only if malloc fails.
 */
AVCollectdClient *av_collectd_client_alloc(void* ctx, const char* address);

/*
 * Free the client allocated with av_collectd_client_alloc.
 */
void av_collectd_client_free(AVCollectdClient **);


/*
 * Attempt to connect if no connection has been made, or enough time has
 * elapsed since the last connection attempt.
 */
int av_collectd_client_connect(AVCollectdClient *client);

/*
 * Send single metric with a single value to collectd.
 * If connection has an error, it will try to reconnect.
 */
void av_collectd_putval(AVCollectdClient*, lcc_value_list_t);

/*
 * Log the provided metric value for debugging purposes.
 */
void av_collectd_print_value_list(AVCollectdClient*, lcc_value_list_t);
