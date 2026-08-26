FROM mysql:8.4

RUN set -eux; \
    microdnf install -y cpio libedit mariadb-connector-c socat; \
    cd /tmp; \
    microdnf download mariadb; \
    mkdir /tmp/mariadb-client; \
    cd /tmp/mariadb-client; \
    rpm2cpio /tmp/mariadb-*.rpm | cpio -idm; \
    cp usr/bin/mariadb usr/bin/mariadb-dump /usr/local/bin/; \
    chmod 0755 /usr/local/bin/mariadb /usr/local/bin/mariadb-dump; \
    /usr/bin/mysql --version; \
    /usr/bin/mysqldump --version; \
    /usr/local/bin/mariadb --version; \
    /usr/local/bin/mariadb-dump --version; \
    microdnf clean all; \
    rm -rf /tmp/mariadb-client /tmp/mariadb-*.rpm

ENTRYPOINT []
