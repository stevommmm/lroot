# lroot

Drop into an interactive shell with an overlayed root filesystem with all writes being redirected to a staging location.

_MUST_ be run as root because of the overlayfs `lowerdir=/`. There might be some way to do it in a user_namespace but I can't work it out.

Seccomp is emplyed to prevent any attempt to use mount syscalls within the isolated shell and undo the work done by overlay to root.

Tries to handle the most common use case being run via sudo, but can be run manually as root by specifying `-sudo-uid` and `-sudo-gid`.

```bash
# Rebecome same invocating user account
sudo ./lroot
# Remain as root inside
sudo ./lroot -sudo-uid 0
```


# Example use

Small console capture of an interactive session showing functioning sudo and the caputred filesystem modifications in the overlay filesystem.

```console
user@host:$ sudo ./lroot
user@namespace$ id
uid=1000(user) gid=1000(user) groups=1000(user)
user@namespace$ sudo pacman -S sl
[sudo] password for user: 
resolving dependencies...
looking for conflicting packages...

Packages (1) sl-5.05-5

Total Download Size:   0.01 MiB
Total Installed Size:  0.02 MiB

:: Proceed with installation? [Y/n] y
:: Retrieving packages...
 sl-5.05-5-x86_64              10.1 KiB  80.1 KiB/s 00:00 [###############################] 100%
(1/1) checking keys in keyring                            [###############################] 100%
(1/1) checking package integrity                          [###############################] 100%
(1/1) loading package files                               [###############################] 100%
(1/1) checking for file conflicts                         [###############################] 100%
(1/1) checking available disk space                       [###############################] 100%
:: Processing package changes...
(1/1) installing sl                                       [###############################] 100%
:: Running post-transaction hooks...
(1/1) Arming ConditionNeedsUpdate...
user@namespace$ exit
exit
2025/01/08 10:08:55 Session ended, changes stored in  /tmp/overlay-root-3045213463/up

user@host$ find /tmp/overlay-root-3045213463/up
/tmp/overlay-root-3045213463/up
/tmp/overlay-root-3045213463/up/etc
/tmp/overlay-root-3045213463/up/etc/pacman.d
/tmp/overlay-root-3045213463/up/etc/pacman.d/gnupg
/tmp/overlay-root-3045213463/up/etc/pacman.d/gnupg/trustdb.gpg
/tmp/overlay-root-3045213463/up/etc/ld.so.cache
/tmp/overlay-root-3045213463/up/var
/tmp/overlay-root-3045213463/up/var/log
/tmp/overlay-root-3045213463/up/var/log/pacman.log
/tmp/overlay-root-3045213463/up/var/lib
/tmp/overlay-root-3045213463/up/var/lib/pacman
/tmp/overlay-root-3045213463/up/var/lib/pacman/local
/tmp/overlay-root-3045213463/up/var/lib/pacman/local/sl-5.05-5
/tmp/overlay-root-3045213463/up/var/lib/pacman/local/sl-5.05-5/mtree
/tmp/overlay-root-3045213463/up/var/lib/pacman/local/sl-5.05-5/desc
/tmp/overlay-root-3045213463/up/var/lib/pacman/local/sl-5.05-5/files
/tmp/overlay-root-3045213463/up/var/cache
/tmp/overlay-root-3045213463/up/var/cache/pacman
/tmp/overlay-root-3045213463/up/var/cache/pacman/pkg
/tmp/overlay-root-3045213463/up/var/cache/pacman/pkg/sl-5.05-5-x86_64.pkg.tar.zst
/tmp/overlay-root-3045213463/up/var/cache/pacman/pkg/sl-5.05-5-x86_64.pkg.tar.zst.sig
/tmp/overlay-root-3045213463/up/var/cache/ldconfig
/tmp/overlay-root-3045213463/up/var/cache/ldconfig/aux-cache
/tmp/overlay-root-3045213463/up/usr
/tmp/overlay-root-3045213463/up/usr/bin
/tmp/overlay-root-3045213463/up/usr/bin/sl
/tmp/overlay-root-3045213463/up/usr/share
/tmp/overlay-root-3045213463/up/usr/share/licenses
/tmp/overlay-root-3045213463/up/usr/share/licenses/sl
/tmp/overlay-root-3045213463/up/usr/share/licenses/sl/LICENSE
/tmp/overlay-root-3045213463/up/usr/share/man
/tmp/overlay-root-3045213463/up/usr/share/man/man1
/tmp/overlay-root-3045213463/up/usr/share/man/man1/sl.1.gz
```