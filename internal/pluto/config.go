package pluto

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	KernelURL         string   `json:"kernelURL"`
	OutdoorToken      string   `json:"outdoorToken"`
	SaturnURL         string   `json:"saturnURL"`
	AccessToken       string   `json:"accessToken"`
	ConnectionName    string   `json:"connectionName"`
	ReleaseRepository string   `json:"releaseRepository"`
	Sources           []string `json:"sources"`
	IntervalSeconds   int      `json:"intervalSeconds"`
	Enabled           bool     `json:"enabled"`
}

func DefaultConfig() Config { return Config{IntervalSeconds: 86400, Sources: []string{}} }
func LoadConfig(filename string) (Config, error) {
	c := DefaultConfig()
	raw, err := os.ReadFile(filename)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if len(raw) > 65536 {
		return c, errors.New("configuration exceeds limit")
	}
	err = json.Unmarshal(raw, &c)
	if err != nil {
		return c, errors.New("configuration is invalid")
	}
	return c, nil
}
func SaveJSON(filename string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(filename), ".pluto-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temp, filename); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(filename))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func HTTPSOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return "", errors.New("an HTTPS origin without a path or credentials is required")
	}
	return "https://" + u.Host, nil
}
func ValidateSources(values []string) ([]string, error) {
	if len(values) < 1 || len(values) > 128 {
		return nil, errors.New("select between 1 and 128 files or folders")
	}
	seen := map[string]bool{}
	result := []string{}
	for _, v := range values {
		v = filepath.Clean(strings.TrimSpace(v))
		if !filepath.IsAbs(v) || v == string(filepath.Separator) {
			return nil, errors.New("select absolute paths, excluding the entire filesystem root")
		}
		info, err := os.Lstat(v)
		if err != nil {
			return nil, errors.New("a selected source is inaccessible")
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return nil, errors.New("sources must be regular files or directories; symbolic links are not followed")
		}
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result, nil
}
