# acme

## What is this?

A pair of services that:

1. Retrieves an updated TLS certificate from Let's Encrypt (`le-update-cert`) and
2. Updates the certificate in the mod_nss database (`update-mod-nss`).

## le-update-cert

A Python 2 script that retrieves an updated certificate **for a single domain** from Let's Encrypt.

Uses the following files and directories.

- `/etc/acme/client.key`- Let's Encrypt client key returned when the domain was originally registered
- `/etc/acme/${HOSTNAME}.csr` - certificate signing request for the domain/hostname
- `/var/lib/acme/${HOSTNAME}.crt` - the most recently downloaded certificate for the domain/hostname
- `/var/lib/acme/${HOSTNAME}.new` - symlink to ${HOSTNAME}.crt; created when a new certificate is retrieved
- `/var/www/acme-challenge` - ACME challenge content directory; must be served as `http://${HOSTNAME}/.well-known/acme-challenge`

Permissions:

~~~
drwx------. 2 acme acme  50 Mar 19 21:12 /etc/acme
drwxr-xr-x. 2 acme acme  67 May 25 10:53 /var/lib/acme
drwxr-xr-x. 3 acme acme 178 May 20 18:40 /var/www/acme-challenge
~~~

## update-mod-nss

A program that atomically (as possible) updates the mod_nss certificate **for a single domain**.

Note that the systemd unit file (`update-mod-nss@.service`) is configured to run this program for a particular domain only if a new certificate symbolic link (`/var/lib/acme/${HOSTNAME}.new`) exists.  If the program completes successfully, the ${HOSTNAME}.new symlink is deleted, and this program will not be run again for $HOSTNAME until a new certificate is downloaded by `le-update-cert`.

The basic process used is:

1. The mod_nss directory (`/etc/httpd/alias`) should be a symlink to a timestamped directory, e.g. `alias -> alias-20170525155308`.
2. Create a new `/etc/httpd/alias-YYYYMMDDHHMMSS` directory, using the current date and time.
3. Copy the NSS database files (`cert8.db`, `key3.db`, and `secmod.db`) from the old mod_nss directory to the new directory.
4. Delete any old certificates for $HOSTNAME from the **new** NSS database.
5. Add the new certificate to the new NSS database.
6. Copy all other files, subdirectories, and symlinks from the old mod_nss directory to the new directory.
7. Create a new symlink (`/etc/httpd/alias.new`) that points to the new mod_nss directory.
8. Rename the new symlink to `/etc/httpd/alias`. (This is an atomic operation.)
9. Delete the old mod_nss directory.
10. Reload httpd (done by systemd as an `ExecStartPost` step).

Build with:
~~~
gcc -O3 -Wall -Wextra -I/usr/include/{nspr4,nss3} -o update-mod-nss update-mod-nss.c -l{nspr4,plds4,nss3,smime3}
~~~

Files and directories:

- `/etc/httpd/alias` - symlink to timestamped mod_nss database directory
- `/etc/httpd/alias-YYYYMMDDHHMMSS` - timestamped mod_nss directory
- `/var/lib/acme/${HOSTNAME}.crt` - the new certificate for the hostname/domain

~~~
# ls -l /etc/httpd
lrwxrwxrwx. 1 root root  20 May 25 10:53 alias -> alias-20170525155308
drwxr-xr-x. 3 root root 226 May 25 10:53 alias-20170525155308
~~~

## SELinux

Build and install the policy module with:

~~~
$ ln -s /usr/share/selinux/devel/Makefile .
$ make
$ sudo semodule -i acme.pp
~~~

File and directory contexts:

~~~
drwx------. acme acme system_u:object_r:acme_etc_t:s0           /etc/acme
lrwxrwxrwx. root root system_u:object_r:cert_t:s0               /etc/httpd/alias -> alias-20170525155308
drwxr-xr-x. root root system_u:object_r:cert_t:s0               /etc/httpd/alias-20170525155308
drwxr-xr-x. acme acme system_u:object_r:acme_var_lib_t:s0       /var/lib/acme
drwxr-xr-x. acme acme system_u:object_r:httpd_acme_content_t:s0 /var/www/acme-challenge
-rwxr-xr-x. root root unconfined_u:object_r:acme_le_exec_t:s0   /usr/local/bin/le-update-cert
-rwxr-xr-x. root root unconfined_u:object_r:acme_nss_exec_t:s0  /usr/local/bin/update-mod-nss

~~~
