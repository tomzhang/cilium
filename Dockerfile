FROM alpine:3.5

LABEL "Maintainer: Andre Martins <andre@cilium.io>"

ADD . /tmp/cilium-net-build/src/github.com/cilium/cilium

RUN apk update && \
apk add curl go coreutils binutils libelf clang iproute2 gcc bash make git \
 linux-headers libc-dev  && \
cd /tmp/cilium-net-build/src/github.com/cilium/cilium && \
export GOPATH=/tmp/cilium-net-build && \
make && \
make PKG_BUILD=1 install && \
apk del curl go binutils make git linux-headers && \
rm -fr /root /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/local/go && \
echo '#!/usr/bin/env bash\ncp /opt/cni/bin/cilium-cni /tmp/cni/bin && /usr/bin/cilium-agent $@' > /home/with-cni.sh && \
chmod +x /home/with-cni.sh

ENV INITSYSTEM="SYSTEMD"

CMD ["/usr/bin/cilium"]
