//go:build linux

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
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
	"btrfs",
	"zfs",
	"f2fs",
	"xfs",
	// "vfat",
}

// Read over the namespace mounts looking for known filesystems to bring across
func read_mountinfo() []string {
	ret := []string{}
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return ret
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), " ")
		if len(parts) >= 2 && parts[1] != "/" && slices.Contains(bindmountfstypes, parts[2]) {
			ret = append(ret, parts[1])
		}
	}
	return ret
}

// Apply seccomp filter to ourselves preventing all the mount related
// syscalls from functioning
func disallowmount() error {
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
		// "umount",
		// "umount2",
	}

	filter, err := libseccomp.NewFilter(libseccomp.ActAllow.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		return err
	}
	filter.SetNoNewPrivsBit(false) // allow sudo inside but still filter mount
	for _, element := range mount_syscalls {
		syscallID, err := libseccomp.GetSyscallFromName(element)
		if err != nil {
			return err
		}
		filter.AddRule(syscallID, libseccomp.ActErrno)
	}
	filter.Load()
	return nil
}

// Re-execute our binary with the parsed args but put the sibling in
// a new mount namespace
func drop_to_userns(root string, uid, gid uint64, network, mindev bool, passpaths []string) {
	cmd := exec.Command("/proc/self/exe", "--stage2", "-chroot", root,
		"-sudo-uid", strconv.FormatUint(uid, 10), "-sudo-gid", strconv.FormatUint(gid, 10),
		fmt.Sprintf("-mindev=%s", strconv.FormatBool(mindev)),
	)
	for _, fp := range passpaths {
		cmd.Args = append(cmd.Args, "-pass", fp)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWPID,
	}
	// If we dont want networking, namespace it too
	if !network {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNET
	}
	must(cmd.Run())
}

// Mount a specific filesystem to the new location via overlay
func isolatefs(root, fs string) string {
	sfs := strings.ReplaceAll(fs, "/", "_")
	newroot := filepath.Join(root, "root", fs)
	upperdir := filepath.Join(root, sfs, "up")
	workdir := filepath.Join(root, sfs, "work")

	log.Println("Mounting", fs, "to", newroot, "/w upper", upperdir)

	must(os.MkdirAll(newroot, 0755))
	must(os.MkdirAll(upperdir, 0755))
	must(os.MkdirAll(workdir, 0755))

	fd, err := unix.Fsopen("overlay", unix.FSOPEN_CLOEXEC)
	if err != nil {
		log.Fatal(err)
	}
	defer unix.Close(fd)

	must(unix.FsconfigSetString(fd, "source", "overlay"))
	must(unix.FsconfigSetString(fd, "lowerdir", fs))
	must(unix.FsconfigSetString(fd, "upperdir", upperdir))
	must(unix.FsconfigSetString(fd, "workdir", workdir))
	// Turn off extras to allow lowerdir to change without issues between usage
	// https://docs.kernel.org/filesystems/overlayfs.html#changes-to-underlying-filesystems
	must(unix.FsconfigSetString(fd, "xino", "off"))
	must(unix.FsconfigSetString(fd, "index", "off"))
	must(unix.FsconfigSetString(fd, "redirect_dir", "off"))
	must(unix.FsconfigSetString(fd, "metacopy", "off"))
	must(unix.FsconfigCreate(fd))
	fsfd, err := unix.Fsmount(fd, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer unix.Close(fsfd)

	must(unix.MoveMount(fsfd, "", unix.AT_FDCWD, newroot, unix.MOVE_MOUNT_F_EMPTY_PATH))

	return newroot
}

func isolate(root string, sudo_uid, sudo_gid uint32, mindev bool, passpaths []string) {
	filesystems := read_mountinfo()
	newroot := isolatefs(root, "/")
	defer unix.Unmount(newroot, unix.MNT_DETACH)

	syscall.Umask(0000)

	// We dont bring /dev/ across so give namespace some devices
	if !mindev {
		must(syscall.Mount("none", filepath.Join(newroot, "/dev/"), "devtmpfs", 0, ""))
	} else {
		must(syscall.Mknod(filepath.Join(newroot, "/dev/null"), syscall.S_IFCHR|0666, int(unix.Mkdev(1, 3))))
		must(syscall.Mknod(filepath.Join(newroot, "/dev/zero"), syscall.S_IFCHR|0666, int(unix.Mkdev(1, 5))))
		must(syscall.Mknod(filepath.Join(newroot, "/dev/random"), syscall.S_IFCHR|0666, int(unix.Mkdev(1, 8))))
		must(syscall.Mknod(filepath.Join(newroot, "/dev/urandom"), syscall.S_IFCHR|0666, int(unix.Mkdev(1, 9))))
	}
	// Overlay every mounted filesystem into the new root. get file handle before chroot
	for _, fs := range filesystems {
		_ = os.MkdirAll(filepath.Join(newroot, fs), 0700)
		defer unix.Unmount(isolatefs(root, fs), unix.MNT_DETACH)
	}

	// Pass through whatever clients requests, wayland socket etc
	passthrough := make(map[string]int)
	for _, fp := range passpaths {
		log.Printf("Passing in %q\n", fp)
		fd, err := unix.OpenTree(unix.AT_FDCWD, fp, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH|unix.AT_RECURSIVE)
		if err != nil {
			log.Fatal(err)
		}
		passthrough[fp] = fd
	}

	// Chroot and reset path into our new fs
	// If chroot fails die - we remove files later on expecting to be in the
	// new root without checking
	must(unix.Chroot(newroot))
	unix.Chdir("/")
	_ = syscall.Sethostname([]byte("namespace"))

	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, ""); err == nil {
		defer unix.Unmount("/proc", unix.MNT_DETACH)
	}
	if err := syscall.Mount("sysfs", "/sys", "sysfs", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, ""); err == nil {
		defer unix.Unmount("/sys", unix.MNT_DETACH)
	}
	if err := syscall.Mount("tmpfs", "/run", "tmpfs", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, ""); err == nil {
		defer unix.Unmount("/run", unix.MNT_DETACH)
	}

	// Mount any passthrough devices via file handle so we dont shadow with /run etc
	for fp, fd := range passthrough {
		_ = os.MkdirAll(filepath.Dir(fp), 0755)
		must(unix.MoveMount(fd, "", unix.AT_FDCWD, filepath.Dir(fp), unix.MOVE_MOUNT_F_EMPTY_PATH))
		syscall.Close(fd)
	}

	// Apply seccomp to prevent remounting everything after all our hard work
	must(disallowmount())

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
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Override vars with sudo vars when we drop
	for _, k := range []string{"HOME", "USER", "UID", "GID"} {
		if v := os.Getenv(fmt.Sprintf("SUDO_%s", k)); v != "" {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd.Run()
}

// Interrogate our effective capabilities for needed privs.
func has_cap_sys_admin() bool {
	hdr := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0, // 0 means 'ourselves'
	}
	var data unix.CapUserData
	if err := unix.Capget(&hdr, &data); err != nil {
		log.Println(err)
		return false
	}

	return (data.Effective & (1 << unix.CAP_SYS_ADMIN)) != 0
}

// Parse an integer from environ key
// Note the int is truncated to uint32 but returns uint64 type for
// ease of use in flag.Uint64
func env_uint64(key string) uint64 {
	if k := os.Getenv(key); k != "" {
		if u64, err := strconv.ParseUint(k, 10, 32); err == nil {
			return u64
		}
	}

	return 0
}

func must(err error) {
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return
		}
		_, file, line, _ := runtime.Caller(1)
		log.Fatalf("FATAL %s:%d %s\n", file, line, err)
	}
}

type PassedPaths []string

func (v *PassedPaths) String() string {
	return ""
}

func (v *PassedPaths) Set(s string) error {
	*v = append(*v, s)
	return nil
}

func main() {
	sudo_uid := flag.Uint64("sudo-uid", env_uint64("SUDO_UID"), "UID to become after chroot.")
	sudo_gid := flag.Uint64("sudo-gid", env_uint64("SUDO_GID"), "GID to become after chroot.")
	chroot := flag.String("chroot", "", "Path to chroot folder structure.")
	network := flag.Bool("network", true, "Use network namespace.")
	mindev := flag.Bool("mindev", true, "Use minimal /dev/ entries.")
	stage2 := flag.Bool("stage2", false, "internal flag")
	passpaths := make(PassedPaths, 0)
	flag.Var(&passpaths, "pass", "Locations to mount post-chroot.")
	flag.Parse()

	if !has_cap_sys_admin() {
		log.Fatal("I dont have CAP_SYS_ADMIN, none of this is going to work.")
	}

	if *chroot == "" {
		*chroot, _ = os.MkdirTemp("", "overlay-root-*")
	}

	if *stage2 {
		isolate(*chroot, uint32(*sudo_uid), uint32(*sudo_gid), *mindev, passpaths)
		log.Println("Session ended, changes stored in ", *chroot)
	} else {
		drop_to_userns(*chroot, *sudo_uid, *sudo_gid, *network, *mindev, passpaths)
		unix.Unmount(filepath.Join(*chroot, "root"), unix.MNT_DETACH)
		// lazy try and set ownership after we're done
		filepath.WalkDir(*chroot, func(path string, d fs.DirEntry, err error) error {
			_ = os.Chown(path, int(*sudo_uid), int(*sudo_gid))
			return nil
		})
	}
}
