#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test.h"

static volatile sig_atomic_t terminated;

static void
on_signal(int s)
{
    (void)s;
    terminated = 1;
    net_raise_event();
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    signal(SIGINT, on_signal); // Ctrl+C SIGINT時のgraceful shutdown
    if (net_init() == -1)
    {
        errorf("net_init() failure");
        return -1;
    }
    dev = loopback_init();
    if (!dev)
    {
        errorf("loopback_init() failure");
        return -1;
    }

    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface)
    {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    debugf("ip_iface_alloc success");
    if (ip_iface_register(dev, iface) == -1)
    {
        errorf("ip_iface_register() failure");
        return -1;
    }
    debugf("ip_iface_register success");

    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev)
    {
        errorf("ether_tap_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface)
    {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1)
    {
        errorf("ip_iface_register() failure");
        return -1;
    }
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1)
    {
        errorf("ip_route_set_default_gateway() failure");
        return -1;
    }
    if (net_run() == -1)
    {
        errorf("net_run() failure");
        return -1;
    }

    return 0;
}

static void
cleanup(void)
{
    net_shutdown();
}

int main(int argc, char *argv[])
{
    struct ip_endpoint local;
    int soc;

    if (setup() == -1)
    {
        errorf("steup() failure");
        return -1;
    }
    ip_endpoint_pton("0.0.0.0:7", &local);
    soc = tcp_open_rfc793(&local, NULL, 0);
    if (soc == -1)
    {
        errorf("tcp_open_rfc793() failure");
        cleanup();
        return -1;
    }
    while (!terminated)
    {
        sleep(1);
    }
    tcp_close(soc);
    cleanup();
    return 0;
}