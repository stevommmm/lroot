package main

import (
	"bufio"
	"flag"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

var bindmountfstypes []string = []string{
	"ext4",
	"ext3",
	"ext2",
	"bcachefs",
	"vfat",
}

// Read over the namespace mounts looking for known filesystems to bring across
func read_mountinfo() []string {
	ret := []string{}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return ret
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), " ")
		if len(parts) >= 8 && parts[4] != "/" && slices.Contains(bindmountfstypes, parts[8]) {
			ret = append(ret, parts[4])
		}
	}
	return ret
}

func disallowmount() {
	mount_syscalls := []string{
		"chroot",
		"fsconfig",
		"fsmount",
		"fsopen",
		"fspick",
		"mount",
		"mount_setattr",
		"move_mount",
		"open_tree",
		"pivot_root",
		"umount",
		"umount2",
	}

	filter, err := libseccomp.NewFilter(libseccomp.ActAllow.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		log.Fatal("Error creating filter: %s\n", err)
	}
	filter.SetNoNewPrivsBit(false) // allow sudo inside but still filter mount
	for _, element := range mount_syscalls {
		syscallID, err := libseccomp.GetSyscallFromName(element)
		if err != nil {
			log.Fatal(err)
		}
		filter.AddRule(syscallID, libseccomp.ActErrno)
	}
	filter.Load()
}

// Reexecute our binary with the parsed args but put the sibling in
// a new mount namespace
func drop_to_userns(root string, uid, gid uint64) {
	cmd := exec.Command("/proc/self/exe", "--stage2", "-chroot", root,
		"-sudo-uid", strconv.FormatUint(uid, 10), "-sudo-gid", strconv.FormatUint(gid, 10),
	)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWPID,
	}
	cmd.Run()
}

func isolate(root string, sudo_uid, sudo_gid uint32) string {
	newroot := filepath.Join(root, "root")
	upperdir := filepath.Join(root, "up")
	workdir := filepath.Join(root, "work")

	_ = os.MkdirAll(newroot, 0755)
	_ = os.MkdirAll(upperdir, 0755)
	_ = os.MkdirAll(workdir, 0755)

	filesystems := read_mountinfo()

	fd, err := unix.Fsopen("overlay", unix.FSOPEN_CLOEXEC)
	if err != nil {
		log.Fatal(err)
	}
	defer unix.Close(fd)

	if err := unix.FsconfigSetString(fd, "source", "overlay"); err != nil {
		log.Fatal(err)
	}
	if err := unix.FsconfigSetString(fd, "lowerdir", "/"); err != nil {
		log.Fatal(err)
	}
	if err := unix.FsconfigSetString(fd, "upperdir", upperdir); err != nil {
		log.Fatal(err)
	}
	if err := unix.FsconfigSetString(fd, "workdir", workdir); err != nil {
		log.Fatal(err)
	}
	if err := unix.FsconfigCreate(fd); err != nil {
		log.Fatal(err)
	}
	fsfd, err := unix.Fsmount(fd, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer unix.Close(fsfd)

	if err := unix.MoveMount(fsfd, "", unix.AT_FDCWD, newroot, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		log.Fatal(err)
	}
	// try cleanup mounts when we exit
	defer unix.Unmount(newroot, 0)

	for _, fs := range filesystems {
		os.MkdirAll(filepath.Join(newroot, fs), 0700)
		
		if err := syscall.Mount(fs, filepath.Join(newroot, fs), "", syscall.MS_BIND, ""); err == nil {
			// Remount readonly - cant be done in one step for some reason
			if err := syscall.Mount("", filepath.Join(newroot, fs), "", syscall.MS_REC|syscall.MS_BIND|syscall.MS_RDONLY|syscall.MS_REMOUNT, ""); err == nil {
				defer unix.Unmount(filepath.Join(newroot, fs), syscall.MNT_DETACH)
			}
		}
	}

	// Bring in needed devices as binds
	if err := syscall.Mount("/dev", filepath.Join(newroot, "/dev"), "", syscall.MS_BIND, ""); err == nil {
		defer unix.Unmount("/dev", unix.MNT_DETACH)
	}
	if err := syscall.Mount("/dev/pts", filepath.Join(newroot, "/dev/pts"), "", syscall.MS_BIND, ""); err == nil {
		defer unix.Unmount("/dev/pts", unix.MNT_DETACH)
	}

	// Chroot and reset path into our new fs
	unix.Chroot(newroot)
	unix.Chdir("/")

	// Bring live utility mounts in
	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, ""); err == nil {
		defer unix.Unmount("/proc", unix.MNT_DETACH)
	}
	if err := syscall.Mount("sysfs", "/sys", "sysfs", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, ""); err == nil {
		defer unix.Unmount("/sys", unix.MNT_DETACH)
	}
	if err := syscall.Mount("tmpfs", "/run", "tmpfs", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, ""); err == nil {
		defer unix.Unmount("/run", unix.MNT_DETACH)
	}

	// Apply seccomp to prevent remounting everything after all our hard work
	disallowmount()

	// Capture children dying and wait so we dont end up with
	// a mass of zombies in the new namespace
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGCHLD)
		for {
			<-c // iter when we get events
			for {
				zom, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil)
				if err != nil || zom == 0 {
					break
				}
				syscall.Wait4(zom, nil, 0, nil)
			}
		}
	}()

	// Drop into the subshell with the sudo uid/gid of that user
	cmd := exec.Command("/bin/bash")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: sudo_uid,
			Gid: sudo_gid,
		},
	}
	cmd.Env = append(os.Environ(),
		"PS1=overlay: ",
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	return upperdir
}

// Parse an integer from environ key
// Note the int is trucated to uint32 but returns uint64 type for
// ease of use in flag.Uint64
func env_uint64(key string) uint64 {
	if k := os.Getenv(key); k != "" {
		if u64, err := strconv.ParseUint(k, 10, 32); err == nil {
			return u64
		}
	}

	return 0
}

func main() {
	sudo_uid := flag.Uint64("sudo-uid", env_uint64("SUDO_UID"), "UID to become after chroot.")
	sudo_gid := flag.Uint64("sudo-gid", env_uint64("SUDO_GID"), "GID to become after chroot.")
	chroot := flag.String("chroot", "", "Path to chroot folder structure.")
	stage2 := flag.Bool("stage2", false, "internal flag")
	flag.Parse()

	if *chroot == "" {
		*chroot, _ = os.MkdirTemp("", "overlay-root-*")
	}

	if *stage2 {
		upper := isolate(*chroot, uint32(*sudo_uid), uint32(*sudo_gid))
		log.Println("Session ended, changes stored in ", upper)
	} else {
		drop_to_userns(*chroot, *sudo_uid, *sudo_gid)
		unix.Unmount(filepath.Join(*chroot, "root"), unix.MNT_DETACH)
		// lazy try and set ownership after we're done
		filepath.WalkDir(*chroot, func(path string, d fs.DirEntry, err error) error {
			_ = os.Chown(path, int(*sudo_uid), int(*sudo_gid))
			return nil
		})
	}
}
