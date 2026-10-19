package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	sdk "github.com/truesignal/sdk-go"
	"golang.org/x/sys/unix"
)

func runInit() {
	filesStr := os.Getenv("TS_DECOY_FILES")
	if filesStr == "" {
		log.Println("TS_DECOY_FILES is empty, nothing to provision.")
		return
	}

	files := strings.Split(filesStr, ",")
	validFiles := 0

	for _, f := range files {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}

		clean := filepath.Clean(f)

		// Basic path validation
		if clean != f ||
			!filepath.IsAbs(f) ||
			strings.Contains(f, "..") ||
			strings.Contains(f, "\x00") {
			log.Printf("ERROR: Invalid decoy file path: %s", f)
			continue
		}

		hostPath := filepath.Join("/host", strings.TrimPrefix(f, "/"))

		// Verify intermediate path components are not symlinks
		parts := strings.Split(strings.TrimPrefix(f, "/"), "/")
		current := "/host"

		symlinkFound := false

		for _, p := range parts {
			if p == "" {
				continue
			}

			current = filepath.Join(current, p)

			info, err := os.Lstat(current)
			if err != nil {
				if !os.IsNotExist(err) {
					log.Printf("ERROR: Failed inspecting path %s: %v", current, err)
					symlinkFound = true
				}
				break
			}

			if info.Mode()&os.ModeSymlink != 0 {
				log.Printf("ERROR: Symlink detected in path: %s", current)
				symlinkFound = true
				break
			}
		}

		if symlinkFound {
			continue
		}

		parent := filepath.Dir(hostPath)

		parentInfo, err := os.Lstat(parent)
		if err != nil {
			log.Printf("ERROR: Parent directory inaccessible: %s (%v)", parent, err)
			continue
		}

		if !parentInfo.IsDir() {
			log.Printf("ERROR: Parent path is not a directory: %s", parent)
			continue
		}

		// Check existing file
		fileInfo, err := os.Lstat(hostPath)
		if err == nil {

			if fileInfo.Mode()&os.ModeSymlink != 0 {
				log.Printf("ERROR: Decoy file is a symlink: %s", hostPath)
				continue
			}

			if !fileInfo.Mode().IsRegular() {
				log.Printf("ERROR: Decoy path is not a regular file: %s", hostPath)
				continue
			}

			log.Printf("Decoy file already exists: %s", hostPath)
			validFiles++
			continue
		}

		// Create file if missing
		if os.IsNotExist(err) {

			dirFD, err := unix.Open(
				parent,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,
				0,
			)

			if err != nil {
				log.Printf("ERROR: Failed opening parent directory %s: %v", parent, err)
				continue
			}

			fd, err := unix.Openat(
				dirFD,
				filepath.Base(hostPath),
				unix.O_CREAT|
					unix.O_EXCL|
					unix.O_WRONLY|
					unix.O_NOFOLLOW|
					unix.O_CLOEXEC,
				0644,
			)

			unix.Close(dirFD)

			if err != nil {
				log.Printf("ERROR: Failed creating decoy file %q: %v", hostPath, err)
				continue
			}

			// Only files created here (O_EXCL) get content: existing host files
			// used as tripwires are never modified.
			if _, err := unix.Write(fd, lureContent(filepath.Base(f))); err != nil {
				log.Printf("WARNING: Failed writing lure content to %q: %v", hostPath, err)
			}
			unix.Close(fd)

			log.Printf("Created decoy file: %q", hostPath)
			validFiles++

		} else {
			log.Printf("ERROR: Failed inspecting file %s: %v", hostPath, err)
		}
	}

	if validFiles == 0 {
		log.Fatalf("FATAL: No valid decoy files could be provisioned.")
	}

	log.Printf("Provisioned %d valid decoy file(s)", validFiles)
}

func reportFileEvent(
	ts *sdk.Sensor,
	trigger string,
	category string,
	action string,
	path string,
) {
	ts.ReportEvent(
		trigger,
		"Local OS",
		filepath.Base(path),
		sdk.EventDetails{
			{Key: "category", Value: category},
			{Key: "action", Value: action},
			{Key: "path", Value: path},
		},
	)

	log.Printf("[%s] %s -> %q", strings.ToUpper(category), action, path)
}

func main() {

	// Init mode
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runInit()
		return
	}

	// Initialize SDK
	ts, err := sdk.NewSensor()
	if err != nil {
		log.Fatalf("FATAL: Failed to initialize sensor: %v", err)
	}

	ts.SetTestPayload(
		"decoy_file_tampered",
		"Wizard Firedrill",
		"Mock Canary File",
		sdk.EventDetails{
			{Key: "test_message", Value: "Wizard triggered a synthetic event firedrill."},
			{Key: "category", Value: "tamper"},
			{Key: "action", Value: "Decoy file modified"},
			{Key: "path", Value: "/canaries/mock_passwords.txt"},
		},
	)

	// Test mode
	if ts.TestMode {
		if ts.RunTestMode() {
			log.Println("Test mode completed successfully.")
			os.Exit(0)
		}

		log.Println("Test mode failed to contact Hub.")
		os.Exit(1)
	}

	alertOnOpen := os.Getenv("TS_ALERT_ON_OPEN") == "true"
	dedupe := newDeduper(time.Duration(envInt("TS_ALERT_COOLDOWN", 10)) * time.Second)
	report := func(trigger, category, action, file string) {
		if dedupe.allow(file+"|"+action, time.Now()) {
			reportFileEvent(ts, trigger, category, action, file)
		}
	}

	decoyFilesStr := os.Getenv("TS_DECOY_FILES")
	if decoyFilesStr == "" {
		log.Println("TS_DECOY_FILES is empty. Nothing to monitor.")
		select {}
	}

	fd, err := unix.InotifyInit()
	if err != nil {
		log.Fatalf("Failed to initialize inotify: %v", err)
	}

	defer unix.Close(fd)

	watchMap := make(map[int]string)

	// Default low-noise tamper detection
	mask := uint32(
		unix.IN_MODIFY |
			unix.IN_ATTRIB |
			unix.IN_DELETE_SELF |
			unix.IN_MOVE_SELF |
			unix.IN_CLOSE_WRITE,
	)

	// Optional access detection
	if alertOnOpen {
		mask |= unix.IN_OPEN | unix.IN_ACCESS
	}

	log.Println("")
	log.Println("=== TrueSignal File Canary ===")
	log.Println("")

	log.Println("[Detection Modes]")
	log.Println("- Tamper Detection: ENABLED")

	if alertOnOpen {
		log.Println("- Access Detection: ENABLED")
	} else {
		log.Println("- Access Detection: DISABLED")
	}

	log.Println("")
	log.Println("[Monitored Files]")

	files := strings.Split(decoyFilesStr, ",")

	for _, f := range files {

		f = strings.TrimSpace(f)

		if f == "" {
			continue
		}

		targetPath := filepath.Join(
			"/canaries",
			strings.TrimPrefix(f, "/"),
		)

		info, err := os.Lstat(targetPath)
		if err != nil {
			log.Printf("WARNING: Canary file missing: %s", targetPath)
			continue
		}

		if !info.Mode().IsRegular() {
			log.Printf("WARNING: Canary target is not a regular file: %s", targetPath)
			continue
		}

		wd, err := unix.InotifyAddWatch(fd, targetPath, mask)
		if err != nil {
			log.Printf("WARNING: Failed monitoring %s: %v", targetPath, err)
			continue
		}

		watchMap[int(wd)] = f

		log.Printf("- %s", f)
	}

	if len(watchMap) == 0 {
		log.Fatalf("FATAL: No valid canary files mounted.")
	}

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {

		var buf [unix.SizeofInotifyEvent * 4096]byte

		for {

			n, err := unix.Read(fd, buf[:])

			if err != nil {

				if err == syscall.EINTR {
					continue
				}

				log.Printf("inotify read error: %v", err)
				return
			}

			offset := 0

			for offset+unix.SizeofInotifyEvent <= n {

				event := (*unix.InotifyEvent)(
					unsafe.Pointer(&buf[offset]),
				)

				fileName, ok := watchMap[int(event.Wd)]

				if ok {

					// Tamper events
					if event.Mask&unix.IN_MODIFY != 0 {
						report("decoy_file_tampered", "tamper", "Decoy file modified", fileName)
					}

					if event.Mask&unix.IN_CLOSE_WRITE != 0 {
						report("decoy_file_tampered", "tamper", "Decoy file modified", fileName)
					}

					if event.Mask&unix.IN_ATTRIB != 0 {
						report("decoy_file_tampered", "tamper", "File attributes changed", fileName)
					}

					if event.Mask&unix.IN_DELETE_SELF != 0 {

						reportFileEvent(
							ts,
							"decoy_file_tampered",
							"tamper",
							"Decoy file deleted",
							fileName,
						)

						log.Fatalf(
							"FATAL: Monitored file deleted: %s",
							fileName,
						)
					}

					if event.Mask&unix.IN_MOVE_SELF != 0 {

						reportFileEvent(
							ts,
							"decoy_file_tampered",
							"tamper",
							"Decoy file moved",
							fileName,
						)

						log.Fatalf(
							"FATAL: Monitored file moved: %s",
							fileName,
						)
					}

					// Optional access events
					if alertOnOpen {

						if event.Mask&unix.IN_OPEN != 0 {
							report("decoy_file_accessed", "access", "Decoy file opened", fileName)
						}

						if event.Mask&unix.IN_ACCESS != 0 {
							report("decoy_file_accessed", "access", "Decoy file read", fileName)
						}
					}
				}

				offset += unix.SizeofInotifyEvent + int(event.Len)
			}
		}
	}()

	// Start sensor
	if err := ts.Start(); err != nil {
		log.Fatalf("FATAL: Failed to sync with Hub: %v", err)
	}

	defer ts.Stop()

	log.Println("")
	log.Println("File Canary active. Listening for events...")

	<-sigChan

	log.Println("Shutting down File Canary...")
}