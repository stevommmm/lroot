# local

Exec into an isolated view of the host operating system. 
An overlayfs is placed over `/` with all writes being redirected to a temporary storage location printed on shell exit.

_MUST_ be run as root because of the overlayfs `lowerdir=/`. There might be some way to do it in a user_namespace but I can't work it out.

Tries to handle the most common use case being run via sudo, but can be run manually as root by specifying `-sudo-uid` and `-sudo-gid`.

```bash
# Rebecome same invocating user account
sudo ./local
# Remain as root inside
sudo ./local -sudo-uid 0
```