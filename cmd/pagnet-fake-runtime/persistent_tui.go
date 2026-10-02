package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Human controls stay in the original persistent endpoint's actual controlling
// terminal. They never write machine JSONL or spawn a second interactive process.
func runPersistentHumanTTY(tty *os.File, sessionID string, write func(string), stopping <-chan struct{}, submit func(string)) {
	fd := int(tty.Fd())
	restore := setRawInput(fd)
	defer restore()
	const prompt = "fake-agent> "
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-winch:
				if cols, rows, err := term.GetSize(fd); err == nil {
					write(fmt.Sprintf("\nresized to %dx%d\n", cols, rows))
				}
			case <-stopping:
				return
			case <-done:
				return
			}
		}
	}()
	write("FAKE AGENT — native session " + sessionID + "\n" + prompt)
	var line []byte
	one := make([]byte, 1)
	readByte := func() (byte, bool) {
		for {
			select {
			case <-stopping:
				return 0, false
			default:
			}
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			n, err := unix.Poll(fds, 250)
			if err == syscall.EINTR {
				continue
			}
			if err != nil || (n > 0 && fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0) {
				return 0, false
			}
			if n == 0 {
				continue
			}
			n, err = tty.Read(one)
			if err != nil || n == 0 {
				return 0, false
			}
			return one[0], true
		}
	}
	for {
		c, ok := readByte()
		if !ok {
			return
		}
		switch c {
		case 3:
			line = nil
			write("\n^C (caught)\n" + prompt)
		case 4:
			write("bye\n")
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
			return
		case 27:
			a, ok := readByte()
			if !ok {
				return
			}
			b, ok := readByte()
			if !ok {
				return
			}
			if a == '[' {
				direction := map[byte]string{'A': "up", 'B': "down", 'C': "right", 'D': "left"}[b]
				if direction != "" {
					write("\narrow: " + direction + "\n" + prompt)
				}
			}
			line = nil
		case 127, 8:
			if len(line) > 0 {
				line = line[:len(line)-1]
				write("\b \b")
			}
		case '\r', '\n':
			text := string(line)
			line = nil
			write("\n")
			switch {
			case text == "":
				write(prompt)
			case text == "exit":
				write("bye\n")
				_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
				return
			case text == "crash":
				os.Exit(1)
			case strings.HasPrefix(text, "echo "):
				write("echo: " + strings.TrimPrefix(text, "echo ") + "\n" + prompt)
			case text == "unicode":
				write("unicode: äöü ñçß emoji: 🚀 ✅\n" + prompt)
			case text == "big":
				for i := 0; i < 512; i++ {
					write(fmt.Sprintf("line %04d: %s\n", i, strings.Repeat("x", 1024)))
				}
				write(prompt)
			case text == "resized":
				if cols, rows, err := term.GetSize(fd); err == nil {
					write(fmt.Sprintf("current size: %dx%d\n%s", cols, rows, prompt))
				}
			default:
				write("you> " + text + "\n")
				submit(text)
			}
		default:
			line = append(line, c)
			write(string(c))
		}
	}
}
