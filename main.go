package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"syscall"
)

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

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	root := path.Join(cwd, ".local/root")
	upper := path.Join(cwd, ".local/upper")
	work := path.Join(cwd, ".local/work")

	opts := fmt.Sprintf(
		"lowerdir=/,upperdir=%s,workdir=%s,userxattr",
		upper, work)

	_ = os.MkdirAll(root, 0755)
	_ = os.MkdirAll(upper, 0755)
	_ = os.MkdirAll(work, 0755)
	log.Println(opts)

	// Recursive private
	log.Println("priv root", syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""))

	log.Println("bind", syscall.Mount("/", root, "none", syscall.MS_REC|syscall.MS_BIND, ""))
	// Remount for RO
	log.Println("bind", syscall.Mount("", root, "", syscall.MS_REC|syscall.MS_BIND|syscall.MS_RDONLY|syscall.MS_REMOUNT, ""))

	log.Println("chrot", syscall.Chroot(root))

	log.Println("overlay", syscall.Mount("overlay", "/", "overlay", 0, opts))
	log.Println("proc", syscall.Mount("proc", "/proc", "proc", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, ""))

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
