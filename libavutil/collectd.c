#include "common.h"
#include "libavutil/collectd.h"
#include "libavutil/time.h"

AVCollectdClient *av_collectd_client_alloc(void* ctx, const char* address) {
    AVCollectdClient *client = av_mallocz(sizeof(AVCollectdClient));
    if (!client) {
        return NULL;
    }

    client->ctx = ctx;
    client->reconnect_delay_us = 5000000;

    if (address) {
        snprintf(client->address, sizeof(client->address), "%s", address);
    } else {
        av_log(ctx, AV_LOG_ERROR, "collectd: no server address provided\n");
    }

    return client;
}

void av_collectd_client_free(AVCollectdClient ** client) {
    if (*client) {
        lcc_disconnect((*client)->conn);
    }

    av_freep(client);
}

int av_collectd_client_connect(AVCollectdClient* client) {
    if (client->connect_attempted_at && client->connect_attempted_at > av_gettime_relative() - client->reconnect_delay_us) {
        return -1;
    }

    // Disconnect and remove existing connection
    if (client->conn) {
        lcc_disconnect(client->conn);
        client->conn = NULL;
    }

    // Attempt new connection
    client->connect_attempted_at = av_gettime_relative();
    int ret = lcc_connect(client->address, &client->conn);

    if (ret == 0) {
        av_log(client->ctx, AV_LOG_VERBOSE, "collectd: connected to %s\n", client->address);
    } else {
        av_log(client->ctx, AV_LOG_WARNING, "collectd: failed connecting to %s\n", client->address);
    }

    return ret;
}

void av_collectd_putval(AVCollectdClient* client, lcc_value_list_t value_list) {
    // No client available, attempt to reconnect
    if (!client->conn) {
        av_collectd_client_connect(client);
    }

    // Can't do anything if there is still no client
    if (!client->conn) {
        return;
    }

    // Attempt to send the values
    int ret = lcc_putval(client->conn, &value_list);

    if (ret == 0) {
        return;
    }

    // Send failed. Print error and attempt to reconnect.

    const char* err = lcc_strerror(client->conn);
    av_log(client->ctx, AV_LOG_WARNING, "failed to send data to collectd: %s\n", err);

    av_collectd_client_connect(client);

    // If there is now a valid connection, try again to send the metric data
    if (client->conn) {
        lcc_putval(client->conn, &value_list);
    }
}

void av_collectd_print_value_list(AVCollectdClient *client, lcc_value_list_t vals) {
  av_log(client->ctx, AV_LOG_INFO, "values:\n");
  av_log(client->ctx, AV_LOG_INFO, "  len = %lu\n", vals.values_len);
  av_log(client->ctx, AV_LOG_INFO, "  time = %.3f\n", vals.time);
  av_log(client->ctx, AV_LOG_INFO, "  interval = %.3f\n", vals.interval);
  av_log(client->ctx, AV_LOG_INFO, "  identifier.host = %s\n", vals.identifier.host);
  av_log(client->ctx, AV_LOG_INFO, "  identifier.plugin = %s\n", vals.identifier.plugin);
  av_log(client->ctx, AV_LOG_INFO, "  identifier.plugin_instance = %s\n", vals.identifier.plugin_instance);
  av_log(client->ctx, AV_LOG_INFO, "  identifier.type = %s\n", vals.identifier.type);
  av_log(client->ctx, AV_LOG_INFO, "  identifier.type_instance = %s\n", vals.identifier.type_instance);

  for (size_t i = 0; i < vals.values_len; i++) {
      value_t val = vals.values[i];
      av_log(client->ctx, AV_LOG_INFO, "  value %lu\n", i);

      int value_type = vals.values_types[i];
      if (value_type == LCC_TYPE_COUNTER) {
          av_log(client->ctx, AV_LOG_INFO, "    counter = %lld\n", val.counter);
      } else if (value_type == LCC_TYPE_ABSOLUTE) {
          av_log(client->ctx, AV_LOG_INFO, "    absolute = %lld\n", val.absolute);
      } else if (value_type == LCC_TYPE_GAUGE) {
          av_log(client->ctx, AV_LOG_INFO, "    gauge = %.5f\n", val.gauge);
      } else {
          av_log(client->ctx, AV_LOG_INFO, "    unknown type %d\n", value_type);
      }
  }
}
