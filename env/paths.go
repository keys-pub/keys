package env

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/pkg/errors"
)

// PathExists returns true if path exists.
func PathExists(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, err
	}
}

// MustAppPath returns AppPath or panics.
func MustAppPath(opt ...PathOption) string {
	path, err := AppPath(opt...)
	if err != nil {
		panic(err)
	}
	return path
}

// AppPath returns path for a files or directory in an app support directory.
//
// darwin:
// env.AppPath(env.Dir("MyApp"), env.File("test.txt"), env.MakeDir())
//   => "~/Library/Application Support/MyApp/test.txt"
//
// windows:
// env.AppPath(env.Dir("MyApp"), env.File("test.txt"), env.MakeDir())
//   => "%LOCALAPPDATA%/MyApp/test.txt"
//
// linux:
// env.AppPath(env.Dir("MyApp"), env.File("test.txt"), env.MakeDir())
//   => "~/.local/share/MyApp/test.txt"
//
func AppPath(opt ...PathOption) (string, error) {
	opts, err := newOptions(opt...)
	if err != nil {
		return "", err
	}
	dir, err := appDir(opts.Dirs...)
	if err != nil {
		return "", err
	}
	if opts.MkDir {
		if err := mkdir(dir); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, opts.File), nil
}

func mkdir(dir string) error {
	exist, err := PathExists(dir)
	if err != nil {
		return err
	}
	if !exist {
		err := os.MkdirAll(dir, 0700)
		if err != nil {
			return err
		}
	}
	return nil
}

func appDir(dirs ...string) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		home, err := HomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", filepath.Join(dirs...)), nil
	case "windows":
		dir := os.Getenv("LOCALAPPDATA")
		if dir == "" {
			return "", errors.Errorf("LOCALAPPDATA not set")
		}
		return filepath.Join(dir, filepath.Join(dirs...)), nil
	case "linux":
		dir := os.Getenv("XDG_DATA_HOME")
		if dir == "" {
			home, err := HomeDir()
			if err != nil {
				return "", err
			}
			dir = filepath.Join(home, ".local", "share", filepath.Join(dirs...))
		}
		return dir, nil
	default:
		return "", errors.Errorf("unsupported platform %s", runtime.GOOS)
	}
}

// LogsPath returns directory for app files.
func LogsPath(opt ...PathOption) (string, error) {
	opts, err := newOptions(opt...)
	if err != nil {
		return "", err
	}
	dir, err := logsDir(opts.Dirs...)
	if err != nil {
		return "", err
	}
	if opts.MkDir {
		if err := mkdir(dir); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, opts.File), nil
}

func logsDir(dirs ...string) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		home, err := HomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Logs", filepath.Join(dirs...)), nil
	case "windows":
		dir := os.Getenv("LOCALAPPDATA")
		if dir == "" {
			return "", errors.Errorf("LOCALAPPDATA not set")
		}
		return filepath.Join(dir, filepath.Join(dirs...)), nil
	case "linux":
		dir := os.Getenv("XDG_DATA_HOME")
		if dir == "" {
			home, err := HomeDir()
			if err != nil {
				return "", err
			}
			dir = filepath.Join(home, ".cache", filepath.Join(dirs...))
		}
		return dir, nil
	default:
		return "", errors.Errorf("unsupported platform %s", runtime.GOOS)
	}
}

// HomeDir returns current user home directory.
// On linux, when running an AppImage, HomeDir can be empty.
func HomeDir() (string, error) {
	// TODO: Switch to UserHomeDir in go 1.12
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return usr.HomeDir, nil
}
