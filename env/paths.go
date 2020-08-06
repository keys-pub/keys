// Package env provides paths on different platforms.
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

// AppPath returns where to store app (data) files.
//
// Darwin: ~/Library/Application Support
// Windows: %LOCALAPPDATA% (~/AppData/Local)
// Linux: ~/.local/share
//
// darwin:
// env.AppPath(env.Dir("MyApp"), env.File("test.txt"), env.Mkdir())
//   => "~/Library/Application Support/MyApp/test.txt"
//
// windows:
// env.AppPath(env.Dir("MyApp"), env.File("test.txt"), env.Mkdir())
//   => "%LOCALAPPDATA%/MyApp/test.txt"
//
// linux:
// env.AppPath(env.Dir("MyApp"), env.File("test.txt"), env.Mkdir())
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
	if opts.Mkdir {
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
		if dir != "" {
			return filepath.Join(dir, filepath.Join(dirs...)), nil
		}
		home, err := HomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "share", filepath.Join(dirs...)), nil
	default:
		return "", errors.Errorf("unsupported platform %s", runtime.GOOS)
	}
}

// ConfigPath returns where to store config files.
//
// Darwin: ~/Library/Application Support
// Windows: %APPDATA% (~/AppData/Roaming)
// Linux: ~/.config
//
// darwin:
// env.ConfigPath(env.Dir("MyApp"), env.File("test.txt"), env.Mkdir())
//   => "~/Library/Application Support/MyApp/test.txt"
//
// windows:
// env.ConfigPath(env.Dir("MyApp"), env.File("test.txt"), env.Mkdir())
//   => "%APPDATA%/MyApp/test.txt"
//
// linux:
// env.ConfigPath(env.Dir("MyApp"), env.File("test.txt"), env.Mkdir())
//   => "~/.config/MyApp/test.txt"
//
func ConfigPath(opt ...PathOption) (string, error) {
	opts, err := newOptions(opt...)
	if err != nil {
		return "", err
	}
	dir, err := configDir(opts.Dirs...)
	if err != nil {
		return "", err
	}
	if opts.Mkdir {
		if err := mkdir(dir); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, opts.File), nil
}

func configDir(dirs ...string) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return appDir(dirs...)
	case "windows":
		dir := os.Getenv("APPDATA")
		if dir == "" {
			return "", errors.Errorf("APPDATA not set")
		}
		return filepath.Join(dir, filepath.Join(dirs...)), nil
	case "linux":
		dir := os.Getenv("XDG_CONFIG_HOME")
		if dir != "" {
			return filepath.Join(dir, filepath.Join(dirs...)), nil
		}
		home, err := HomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".config", filepath.Join(dirs...)), nil
	default:
		return "", errors.Errorf("unsupported platform %s", runtime.GOOS)
	}
}

// LogsPath returns directory for log files.
//
// Darwin: ~/Library/Logs
// Windows: %LOCALAPPDATA% (~/AppData/Local)
// Linux: ~/.cache
//
// darwin:
// env.AppPath(env.Dir("MyApp"), env.File("test.txt"), env.Mkdir())
//   => "~/Library/Application Support/MyApp/test.txt"
//
// windows:
// env.AppPath(env.Dir("MyApp"), env.File("test.txt"), env.Mkdir())
//   => "%LOCALAPPDATA%/MyApp/test.txt"
//
// linux:
// env.AppPath(env.Dir("MyApp"), env.File("test.txt"), env.Mkdir())
//   => "~/.cache/MyApp/test.txt"
//
func LogsPath(opt ...PathOption) (string, error) {
	opts, err := newOptions(opt...)
	if err != nil {
		return "", err
	}
	dir, err := logsDir(opts.Dirs...)
	if err != nil {
		return "", err
	}
	if opts.Mkdir {
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
		dir := os.Getenv("XDG_CACHE_HOME")
		if dir != "" {
			return filepath.Join(dir, filepath.Join(dirs...)), nil
		}
		home, err := HomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".cache", filepath.Join(dirs...)), nil
	default:
		return "", errors.Errorf("unsupported platform %s", runtime.GOOS)
	}
}

// HomeDir returns current user home directory.
// On linux, when running an AppImage, HomeDir can be empty string.
func HomeDir() (string, error) {
	// TODO: Switch to UserHomeDir in go 1.12
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return usr.HomeDir, nil
}

// MustHomeDir returns current user home directory.
func MustHomeDir() string {
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}
	return usr.HomeDir
}

// All returns all (unique) directories for the environment.
func All(dir ...string) ([]string, error) {
	dirs := []string{}
	appDir, err := AppPath(Dir(dir...))
	if err != nil {
		return nil, err
	}
	dirs = append(dirs, appDir)

	configDir, err := ConfigPath(Dir(dir...))
	if err != nil {
		return nil, err
	}
	if !contains(dirs, configDir) {
		dirs = append(dirs, configDir)
	}

	logsDir, err := LogsPath(Dir(dir...))
	if err != nil {
		return nil, err
	}
	if !contains(dirs, logsDir) {
		dirs = append(dirs, logsDir)
	}

	return dirs, nil
}

func contains(arr []string, s string) bool {
	for _, a := range arr {
		if s == a {
			return true
		}
	}
	return false
}
