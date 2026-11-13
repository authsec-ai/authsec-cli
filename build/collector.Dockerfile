# authsec/iga-host-collector: authsec-cli as the AuthSec host collector
# (authsec-local). Build: make collector-image.
#
# The console's enrollment command runs it as
#   docker run -d --name authsec-collector --privileged --pid host \
#     -e AUTHSEC_URL=... -v authsec-collector-state:/var/lib/authsec-local \
#     authsec/iga-host-collector:latest \
#     sh -c 'printf "%s" "<token>" > /tmp/t && exec authsec-local run --enrollment-token-file /tmp/t'
# That observes and reports. To also enforce on the host (nftables in the
# host's network, the agents' cgroups), add --network host --cgroupns host.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nftables ca-certificates && rm -rf /var/lib/apt/lists/*
COPY authsec-cli /usr/local/bin/authsec-cli
RUN ln -s authsec-cli /usr/local/bin/authsec-local
VOLUME /var/lib/authsec-local
ENTRYPOINT []
CMD ["authsec-local", "run"]
