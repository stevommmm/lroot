package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	// "runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"io/fs"

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
		if len(parts) >= 7 && parts[4] != "/" && slices.Contains(bindmountfstypes, parts[7]) {
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
		fmt.Printf("Error creating filter: %s\n", err)
	}
	for _, element := range mount_syscalls {
		syscallID, err := libseccomp.GetSyscallFromName(element)
		if err != nil {
			log.Fatal(err)
		}
		filter.AddRule(syscallID, libseccomp.ActErrno)
	}
	filter.Load()
	log.Println("Blocked mounting with seccomp")
}

func drop_to_userns(root string, uid, gid uint64) {
	log.Println("User namespace")
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
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	// unix.Unshare(unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS)

	// log.Println("priv root", syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""))
	log.Println("Overlay:", root)

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
		log.Println("bind", fs, syscall.Mount(fs, filepath.Join(newroot, fs), "", syscall.MS_BIND, ""))
		log.Println("ro-bind", fs, syscall.Mount("", filepath.Join(newroot, fs), "", syscall.MS_REC|syscall.MS_BIND|syscall.MS_RDONLY|syscall.MS_REMOUNT, ""))
	}

	// Bring in needed devices as binds
	log.Println("dev", syscall.Mount("/dev", filepath.Join(newroot, "/dev"), "", syscall.MS_BIND, ""))
	defer unix.Unmount("/dev", unix.MNT_DETACH)
	log.Println("devpts", syscall.Mount("/dev/pts", filepath.Join(newroot, "/dev/pts"), "", syscall.MS_BIND, ""))
	defer unix.Unmount("/dev/pts", unix.MNT_DETACH)

	// os.MkdirAll(filepath.Join(newroot, "old"), 0700)
	// if err := unix.PivotRoot(newroot, filepath.Join(newroot, "old")); err != nil {
	// 	log.Fatal(err)
	// }

	unix.Chroot(newroot)
	unix.Chdir("/")

	log.Println("proc", syscall.Mount("proc", "/proc", "proc", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, ""))
	defer unix.Unmount("/proc", unix.MNT_DETACH)
	log.Println("sysfs", syscall.Mount("sysfs", "/sys", "sysfs", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, ""))
	defer unix.Unmount("/sys", unix.MNT_DETACH)
	log.Println("run", syscall.Mount("tmpfs", "/run", "tmpfs", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, ""))
	defer unix.Unmount("/run", unix.MNT_DETACH)

	// Apply seccomp to prevent remounting everything after all our hard work
	disallowmount()

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

	return newroot
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
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	sudo_uid := flag.Uint64("sudo-uid", env_uint64("SUDO_UID"), "UID to become after chroot.")
	sudo_gid := flag.Uint64("sudo-gid", env_uint64("SUDO_GID"), "GID to become after chroot.")
	chroot := flag.String("chroot", "", "Path to chroot folder structure.")
	stage2 := flag.Bool("stage2", false, "internal flag")
	flag.Parse()

	if *chroot == "" {
		*chroot, _ = os.MkdirTemp("", "overlay-root-*")
	}

	if *stage2 {
		log.Println(isolate(*chroot, uint32(*sudo_uid), uint32(*sudo_gid)))
	} else {
		log.Println("Dropping to namespace")
		drop_to_userns(*chroot, *sudo_uid, *sudo_gid)
		unix.Unmount(filepath.Join(*chroot, "root"), unix.MNT_DETACH)
		// lazy try and set ownership after we're done
		filepath.WalkDir(*chroot, func(path string, d fs.DirEntry, err error) error {
			_ = os.Chown(path, int(*sudo_uid), int(*sudo_gid))
			return nil
		})
	}
}
