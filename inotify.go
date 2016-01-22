// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package inotify // copied from github.com/go-fsnotify/fsnotify

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// Event represents a single file system notification.
type Event struct {
	Mask   uint32 // File operation that triggered the event.
	Cookie uint32 // Unique cookie associating related events (for rename(2))
	Name   string // Relative path to the file or directory.
}

// Watcher watches a set of files, delivering events to a channel.
type Watcher struct {
	Events   chan Event
	Errors   chan error
	mu       sync.Mutex // Map access
	cv       *sync.Cond // sync removing on rm_watch with IN_IGNORE
	fd       int
	poller   *fdPoller
	watches  map[string]*watch // Map of inotify watches (key: path)
	paths    map[int]string    // Map of watched paths (key: watch descriptor)
	done     chan struct{}     // Channel for sending a "quit message" to the reader goroutine
	doneResp chan struct{}     // Channel to respond to Close
}

// NewWatcher establishes a new watcher with the underlying OS and begins waiting for events.
func NewWatcher() (*Watcher, error) {
	// Create inotify fd
	fd, errno := syscall.InotifyInit()
	if fd == -1 {
		return nil, errno
	}
	// Create epoll
	poller, err := newFdPoller(fd)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	w := &Watcher{
		fd:       fd,
		poller:   poller,
		watches:  make(map[string]*watch),
		paths:    make(map[int]string),
		Events:   make(chan Event),
		Errors:   make(chan error),
		done:     make(chan struct{}),
		doneResp: make(chan struct{}),
	}
	w.cv = sync.NewCond(&w.mu)

	go w.readEvents()
	return w, nil
}

func (w *Watcher) isClosed() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

// Close removes all watches and closes the events channel.
func (w *Watcher) Close() error {
	if w.isClosed() {
		return nil
	}

	// Send 'close' signal to goroutine, and set the Watcher to closed.
	close(w.done)

	// Wake up goroutine
	w.poller.wake()

	// Wait for goroutine to close
	<-w.doneResp

	return nil
}

// Add starts watching the named file or directory (non-recursively).
func (w *Watcher) Add(name string) error {
	name = filepath.Clean(name)
	if w.isClosed() {
		return errors.New("inotify instance already closed")
	}

	var flags uint32 = ALL_EVENTS

	w.mu.Lock()
	watchEntry, found := w.watches[name]
	w.mu.Unlock()
	if found {
		watchEntry.flags |= flags
		flags |= syscall.IN_MASK_ADD
	}
	wd, errno := syscall.InotifyAddWatch(w.fd, name, flags)
	if wd == -1 {
		return errno
	}

	w.mu.Lock()
	w.watches[name] = &watch{wd: uint32(wd), flags: flags}
	w.paths[wd] = name
	w.mu.Unlock()

	return nil
}

// Remove stops watching the named file or directory (non-recursively).
func (w *Watcher) Remove(name string) error {
	name = filepath.Clean(name)

	// Fetch the watch.
	w.mu.Lock()
	defer w.mu.Unlock()
	watch, ok := w.watches[name]

	// Remove it from inotify.
	if !ok {
		return fmt.Errorf("can't remove non-existent inotify watch for: %s", name)
	}
	// inotify_rm_watch will return EINVAL if the file has been deleted;
	// the inotify will already have been removed.
	// watches and pathes are deleted in ignoreLinux() implicitly and asynchronously
	// by calling inotify_rm_watch() below. e.g. readEvents() goroutine receives IN_IGNORE
	// so that EINVAL means that the wd is being rm_watch()ed or its file removed
	// by another thread and we have not received IN_IGNORE event.
	success, errno := syscall.InotifyRmWatch(w.fd, watch.wd)
	if success == -1 {
		// TODO: Perhaps it's not helpful to return an error here in every case.
		// the only two possible errors are:
		// EBADF, which happens when w.fd is not a valid file descriptor of any kind.
		// EINVAL, which is when fd is not an inotify descriptor or wd is not a valid watch descriptor.
		// Watch descriptors are invalidated when they are removed explicitly or implicitly;
		// explicitly by inotify_rm_watch, implicitly when the file they are watching is deleted.
		return errno
	}

	// wait until ignoreLinux() deleting maps
	exists := true
	for exists {
		w.cv.Wait()
		_, exists = w.watches[name]
	}

	return nil
}

type watch struct {
	wd    uint32 // Watch descriptor (as returned by the inotify_add_watch() syscall)
	flags uint32 // inotify flags of this watch (see inotify(7) for the list of valid flags)
}

// readEvents reads from the inotify file descriptor, converts the
// received events into Event objects and sends them via the Events channel
func (w *Watcher) readEvents() {
	var (
		buf   [syscall.SizeofInotifyEvent * 4096]byte // Buffer for a maximum of 4096 raw events
		n     int                                     // Number of bytes read with read()
		errno error                                   // Syscall errno
		ok    bool                                    // For poller.wait
	)

	defer close(w.doneResp)
	defer close(w.Errors)
	defer close(w.Events)
	defer syscall.Close(w.fd)
	defer w.poller.close()

	for {
		// See if we have been closed.
		if w.isClosed() {
			return
		}

		ok, errno = w.poller.wait()
		if errno != nil {
			select {
			case w.Errors <- errno:
			case <-w.done:
				return
			}
			continue
		}

		if !ok {
			continue
		}

		n, errno = syscall.Read(w.fd, buf[:])
		// If a signal interrupted execution, see if we've been asked to close, and try again.
		// http://man7.org/linux/man-pages/man7/signal.7.html :
		// "Before Linux 3.8, reads from an inotify(7) file descriptor were not restartable"
		if errno == syscall.EINTR {
			continue
		}

		// syscall.Read might have been woken up by Close. If so, we're done.
		if w.isClosed() {
			return
		}

		if n < syscall.SizeofInotifyEvent {
			var err error
			if n == 0 {
				// If EOF is received. This should really never happen.
				err = io.EOF
			} else if n < 0 {
				// If an error occured while reading.
				err = errno
			} else {
				// Read was too short.
				err = errors.New("notify: short read in readEvents()")
			}
			select {
			case w.Errors <- err:
			case <-w.done:
				return
			}
			continue
		}

		var offset uint32
		// We don't know how many events we just read into the buffer
		// While the offset points to at least one whole event...
		for offset <= uint32(n-syscall.SizeofInotifyEvent) {
			// Point "raw" to the event in the buffer
			raw := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))

			mask := uint32(raw.Mask)
			nameLen := uint32(raw.Len)
			// If the event happened to the watched directory or the watched file, the kernel
			// doesn't append the filename to the event, but we would like to always fill the
			// the "Name" field with a valid filename. We retrieve the path of the watch from
			// the "paths" map.
			w.mu.Lock()
			name := w.paths[int(raw.Wd)]
			w.mu.Unlock()
			if nameLen > 0 {
				// Point "bytes" at the first byte of the filename
				bytes := (*[syscall.PathMax]byte)(unsafe.Pointer(&buf[offset+syscall.SizeofInotifyEvent]))
				// The filename is padded with NULL bytes. TrimRight() gets rid of those.
				name += "/" + strings.TrimRight(string(bytes[0:nameLen]), "\000")
			}

			event := Event{Name: name, Mask: mask, Cookie: uint32(raw.Cookie)}

			// Send the events that are not ignored on the events channel
			if !event.ignoreLinux(w, raw.Wd, mask) {
				select {
				case w.Events <- event:
				case <-w.done:
					return
				}
			}

			// Move to the next event in the buffer
			offset += syscall.SizeofInotifyEvent + nameLen
		}
	}
}

// Certain types of events can be "ignored" and not sent over the Events
// channel. Such as events marked ignore by the kernel, or MODIFY events
// against files that do not exist.
func (e *Event) ignoreLinux(w *Watcher, wd int32, mask uint32) bool {
	// Ignore anything the inotify API says to ignore
	if mask&IGNORED == IGNORED {
		w.mu.Lock()
		defer w.mu.Unlock()
		name := w.paths[int(wd)]
		delete(w.paths, int(wd))
		delete(w.watches, name)
		w.cv.Broadcast()
		return true
	}

	// If the event is not a DELETE or RENAME, the file must exist.
	// Otherwise the event is ignored.
	// *Note*: this was put in place because it was seen that a MODIFY
	// event was sent after the DELETE. This ignores that MODIFY and
	// assumes a DELETE will come or has come if the file doesn't exist.
	remove := mask&DELETE_SELF == DELETE_SELF || mask&DELETE == DELETE
	rename := mask&MOVE_SELF == MOVE_SELF || mask&MOVED_FROM == MOVED_FROM
	if !(remove || rename) {
		_, statErr := os.Lstat(e.Name)
		return os.IsNotExist(statErr)
	}
	return false
}

func (e *Event) IsCreate() bool {
	return e.Mask&CREATE == CREATE || e.Mask&MOVED_TO == MOVED_TO
}

func (e *Event) IsRemove() bool {
	return e.Mask&DELETE_SELF == DELETE_SELF || e.Mask&DELETE == DELETE
}

func (e *Event) IsWrite() bool {
	return e.Mask&MODIFY == MODIFY
}

func (e *Event) IsRename() bool {
	return e.Mask&MOVE_SELF == MOVE_SELF || e.Mask&MOVED_FROM == MOVED_FROM
}

func (e *Event) IsChmod() bool {
	return e.Mask&ATTRIB == ATTRIB
}

// String formats the event in the form
// "filename: 0xEventMask = ACCESS|ATTRIB_|..."
func (e *Event) String() string {
	var events string = ""

	m := e.Mask
	for _, b := range eventBits {
		if m&b.Value == b.Value {
			m &^= b.Value
			events += "|" + b.Name
		}
	}

	if m != 0 {
		events += fmt.Sprintf("|%#x", m)
	}
	if len(events) > 0 {
		events = " == " + events[1:]
	}

	return fmt.Sprintf("%q: %#x%s", e.Name, e.Mask, events)
}

const (
	// Options for inotify_init() are not exported
	// CLOEXEC    uint32 = syscall.IN_CLOEXEC
	// NONBLOCK   uint32 = syscall.IN_NONBLOCK

	// Options for AddWatch
	DONT_FOLLOW uint32 = syscall.IN_DONT_FOLLOW
	ONESHOT     uint32 = syscall.IN_ONESHOT
	ONLYDIR     uint32 = syscall.IN_ONLYDIR

	// The "IN_MASK_ADD" option is not exported, as AddWatch
	// adds it automatically, if there is already a watch for the given path
	// MASK_ADD      uint32 = syscall.IN_MASK_ADD

	// Events
	ACCESS        uint32 = syscall.IN_ACCESS
	ALL_EVENTS    uint32 = syscall.IN_ALL_EVENTS
	ATTRIB        uint32 = syscall.IN_ATTRIB
	CLOSE         uint32 = syscall.IN_CLOSE
	CLOSE_NOWRITE uint32 = syscall.IN_CLOSE_NOWRITE
	CLOSE_WRITE   uint32 = syscall.IN_CLOSE_WRITE
	CREATE        uint32 = syscall.IN_CREATE
	DELETE        uint32 = syscall.IN_DELETE
	DELETE_SELF   uint32 = syscall.IN_DELETE_SELF
	MODIFY        uint32 = syscall.IN_MODIFY
	MOVE          uint32 = syscall.IN_MOVE
	MOVED_FROM    uint32 = syscall.IN_MOVED_FROM
	MOVED_TO      uint32 = syscall.IN_MOVED_TO
	MOVE_SELF     uint32 = syscall.IN_MOVE_SELF
	OPEN          uint32 = syscall.IN_OPEN

	// Special events
	ISDIR      uint32 = syscall.IN_ISDIR
	IGNORED    uint32 = syscall.IN_IGNORED
	Q_OVERFLOW uint32 = syscall.IN_Q_OVERFLOW
	UNMOUNT    uint32 = syscall.IN_UNMOUNT
)

var eventBits = []struct {
	Value uint32
	Name  string
}{
	{ACCESS, "ACCESS"},
	{ATTRIB, "ATTRIB"},
	{CLOSE, "CLOSE"},
	{CLOSE_NOWRITE, "CLOSE_NOWRITE"},
	{CLOSE_WRITE, "CLOSE_WRITE"},
	{CREATE, "CREATE"},
	{DELETE, "DELETE"},
	{DELETE_SELF, "DELETE_SELF"},
	{MODIFY, "MODIFY"},
	{MOVE, "MOVE"},
	{MOVED_FROM, "MOVED_FROM"},
	{MOVED_TO, "MOVED_TO"},
	{MOVE_SELF, "MOVE_SELF"},
	{OPEN, "OPEN"},
	{ISDIR, "ISDIR"},
	{IGNORED, "IGNORED"},
	{Q_OVERFLOW, "Q_OVERFLOW"},
	{UNMOUNT, "UNMOUNT"},
}
