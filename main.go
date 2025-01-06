package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

var ignoremounts []string = []string{
	"sysfs",
	"tmpfs",
	"bdev",
	"proc",
	"cgroup",
	"cgroup2",
	"devtmpfs",
	"binfmt_misc",
	"configfs",
	"debugfs",
	"tracefs",
	"securityfs",
	"sockfs",
	"bpf",
	"pipefs",
	"ramfs",
	"hugetlbfs",
	"devpts",
	"autofs",
	"fuseblk",
	"fuse",
	"fuse.portal",
	"fuse.gvfsd-fuse",
	"fusectl",
	"virtiofs",
	"efivarfs",
	"mqueue",
	"pstore",
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
		if len(parts) >= 7 && parts[4] != "/" && !slices.Contains(ignoremounts, parts[7]) {
			ret = append(ret, parts[4])
			log.Println(parts[4], parts[7])
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

func drop_to_userns() {
	log.Println("User namespace")
	cmd := exec.Command("/proc/self/exe", flag.Args()...)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Env = append(os.Environ(),
		"STAGE=userns",
	)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER |
			syscall.CLONE_NEWNS |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getuid(),
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getgid(),
				Size:        1,
			},
		},
	}
	cmd.Run()
}

func remount() {
	log.Println("Remounting")

	root, _ := os.MkdirTemp("", "overlay-root-*")
	defer os.RemoveAll(root) // clean up

	// Recursive private
	log.Println("priv root", syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""))
	filesystems := read_mountinfo()

	log.Println("bind", syscall.Mount("/", root, "none", syscall.MS_REC|syscall.MS_BIND, ""))
	// Remount for RO
	log.Println("ro", syscall.Mount("", root, "", syscall.MS_REC|syscall.MS_BIND|syscall.MS_RDONLY|syscall.MS_REMOUNT, ""))

	for _, fs := range filesystems {
		log.Println("ro", fs, syscall.Mount("", path.Join(root, fs), "", syscall.MS_REC|syscall.MS_BIND|syscall.MS_RDONLY|syscall.MS_REMOUNT, ""))
	}

	// log.Println("overlay", syscall.Mount("overlay", root, "overlay", syscall.MS_NOATIME, opts))

	log.Println("chroot", syscall.Chroot(root))
	log.Println("proc", syscall.Mount("proc", "/proc", "proc", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, ""))

	disallowmount()

	cmd := exec.Command("/bin/bash", flag.Args()...)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}


func main() {
	flag.Parse()
	log.Println(os.Getpid(), os.Getenv("STAGE"))
	switch os.Getenv("STAGE") {
	case "userns":
		remount()
	default:
		drop_to_userns()
	}
	log.Println("Done")
}
