# local

Drop into an interactive shell with an overlayed root filesystem with all writes being redirected to a staging location.

_MUST_ be run as root because of the overlayfs `lowerdir=/`. There might be some way to do it in a user_namespace but I can't work it out.

Seccomp is emplyed to prevent any attempt to use mount syscalls within the isolated shell and undo the work done by overlay to root.

Tries to handle the most common use case being run via sudo, but can be run manually as root by specifying `-sudo-uid` and `-sudo-gid`.

```bash
# Rebecome same invocating user account
sudo ./local
# Remain as root inside
sudo ./local -sudo-uid 0
```


# Example use

Small console capture of an interactive session showing functioning sudo and the caputred filesystem modifications in the overlay filesystem.

```console
$user> sudo ./local 
2025/01/07 15:42:40 main.go:226: Dropping to namespace
2025/01/07 15:42:40 main.go:81: User namespace
2025/01/07 15:42:40 main.go:105: Overlay: /tmp/overlay-root-928566530
2025/01/07 15:42:40 main.go:157: dev <nil>
2025/01/07 15:42:40 main.go:159: devpts <nil>
2025/01/07 15:42:40 main.go:170: proc <nil>
2025/01/07 15:42:40 main.go:172: sysfs <nil>
2025/01/07 15:42:40 main.go:174: run <nil>
2025/01/07 15:42:40 main.go:77: Blocked mounting with seccomp
bash: /root/.bashrc: Permission denied
$user> sudo -i
[sudo] password for user: 
$root> exit
$user> exit
2025/01/07 15:43:02 main.go:224: /tmp/overlay-root-928566530/root

$user> find /tmp/overlay-root-928566530/up
/tmp/overlay-root-928566530/up
/tmp/overlay-root-928566530/up/root
/tmp/overlay-root-928566530/up/root/.bash_history