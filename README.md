# lroot

Drop into an interactive shell with an overlayed root filesystem with all writes being redirected to a staging location.

_MUST_ be run as root because of the overlayfs `lowerdir=/`. There might be some way to do it in a user_namespace but I can't work it out.

Seccomp is employed to prevent any attempt to use mount syscalls within the isolated shell and undo the work done by overlay to root.

Tries to handle the most common use case being run via sudo, but can be run manually as root by specifying `-sudo-uid` and `-sudo-gid`.

```bash
# Rebecome same invocating user account
sudo ./lroot
# Remain as root inside
sudo ./lroot -sudo-uid 0
# Specify where to store the overlay
sudo ./lroot -chroot .fs
# Without any networking
sudo ./lroot -network=false
# Pass in wayland sock for UI apps
sudo ./lroot -pass=/run/user/1000; export XDG_RUNTIME_DIR=/run/user/1000; firefox
```


# Example use

Small console capture of an interactive session showing functioning sudo and the captured filesystem modifications in the overlay filesystem.

```console
user@host:$ sudo ./lroot
2025/01/08 13:55:01 Mounting / to /tmp/overlay-root-2816698124/root /w upper /tmp/overlay-root-2816698124/_/up
2025/01/08 13:55:01 Mounting /home to /tmp/overlay-root-2816698124/root/home /w upper /tmp/overlay-root-2816698124/_home/up
user@namespace:$ id
uid=1000(user) gid=1000(user) groups=1000(user)
user@namespace:$ sudo pacman -S sl
[sudo] password for user: 
resolving dependencies...
looking for conflicting packages...

Packages (1) sl-5.05-5

Total Download Size:   0.01 MiB
Total Installed Size:  0.02 MiB

:: Proceed with installation? [Y/n] y
:: Retrieving packages...
 sl-5.05-5-x86_64              10.1 KiB   112 KiB/s 00:00 [###############################] 100%
(1/1) checking keys in keyring                            [###############################] 100%
(1/1) checking package integrity                          [###############################] 100%
(1/1) loading package files                               [###############################] 100%
(1/1) checking for file conflicts                         [###############################] 100%
(1/1) checking available disk space                       [###############################] 100%
:: Processing package changes...
(1/1) installing sl                                       [###############################] 100%
:: Running post-transaction hooks...
(1/1) Arming ConditionNeedsUpdate...
user@namespace:$ exit
exit
2025/01/08 13:55:13 Session ended, changes stored in  /tmp/overlay-root-2816698124

user@host:$ find /tmp/overlay-root-2816698124 -type f
/tmp/overlay-root-2816698124/_/up/etc/pacman.d/gnupg/trustdb.gpg
/tmp/overlay-root-2816698124/_/up/etc/ld.so.cache
/tmp/overlay-root-2816698124/_/up/var/log/pacman.log
/tmp/overlay-root-2816698124/_/up/var/lib/pacman/local/sl-5.05-5/mtree
/tmp/overlay-root-2816698124/_/up/var/lib/pacman/local/sl-5.05-5/desc
/tmp/overlay-root-2816698124/_/up/var/lib/pacman/local/sl-5.05-5/files
/tmp/overlay-root-2816698124/_/up/var/cache/pacman/pkg/sl-5.05-5-x86_64.pkg.tar.zst
/tmp/overlay-root-2816698124/_/up/var/cache/pacman/pkg/sl-5.05-5-x86_64.pkg.tar.zst.sig
/tmp/overlay-root-2816698124/_/up/var/cache/ldconfig/aux-cache
/tmp/overlay-root-2816698124/_/up/usr/bin/sl
/tmp/overlay-root-2816698124/_/up/usr/share/licenses/sl/LICENSE
/tmp/overlay-root-2816698124/_/up/usr/share/man/man1/sl.1.gz
```
