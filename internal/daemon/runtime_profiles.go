package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/runtimeprofile"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

type loadedRuntimeProfile struct {
	config  runtimeprofile.Profile
	adapter agentruntime.Adapter
	driver  session.Driver
}
type qwenProfileDriver struct {
	*agentruntime.QwenPersistent
	key domain.RuntimeName
}

func (d *qwenProfileDriver) Name() domain.RuntimeName { return d.key }

type codexProfileDriver struct {
	*agentruntime.CodexPersistent
	key domain.RuntimeName
}

func (d *codexProfileDriver) Name() domain.RuntimeName { return d.key }
func (d *Daemon) loadRuntimeProfiles() error {
	file, err := runtimeprofile.Load(filepath.Join(d.StateDir, runtimeprofile.Filename))
	if err != nil {
		return err
	}
	d.runtimeProfiles = map[string]*loadedRuntimeProfile{}
	for _, cfg := range file.Profiles {
		profile := &loadedRuntimeProfile{config: cfg}
		d.runtimeProfiles[cfg.Name] = profile
		dirs := cfg.Directories()
		for _, dir := range dirs {
			resolved := dir
			if actual, err := filepath.EvalSymlinks(dir); err == nil {
				resolved = actual
			}
			state, _ := filepath.Abs(d.StateDir)
			if actual, err := filepath.EvalSymlinks(state); err == nil {
				state = actual
			}
			rel, err := filepath.Rel(resolved, state)
			if err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))) {
				return fmt.Errorf("runtime profile %q cannot grant access to daemon state", cfg.Name)
			}
		}
		binary, available := cfg.ResolvedExecutable()
		if !available {
			continue
		}
		env := append(append([]string(nil), d.RuntimeEnv...), cfg.Environment()...)
		key := domain.RuntimeName(string(cfg.Runtime) + "@" + cfg.Name)
		switch cfg.Runtime {
		case domain.RuntimeClaudeCode:
			ad := agentruntime.NewClaude(binary)
			ad.Env = env
			ad.PrefixArgs = append([]string(nil), cfg.Args...)
			ad.NativeDirs = dirs
			ad.SetLifecycle(d.sup)
			profile.adapter = ad
		case domain.RuntimeOpenCode:
			ad := agentruntime.NewOpenCode(binary)
			ad.Env = env
			ad.PrefixArgs = append([]string(nil), cfg.Args...)
			ad.NativeDirs = dirs
			ad.SetLifecycle(d.sup)
			profile.adapter = ad
		case domain.RuntimeQwenCode:
			drv := agentruntime.NewQwenPersistent(binary)
			drv.Env = env
			drv.PrefixArgs = append([]string(nil), cfg.Args...)
			drv.NativeDirs = dirs
			drv.SetLifecycle(d.sup)
			drv.PTYAvailable = d.adoptEndpointPTY
			profile.driver = &qwenProfileDriver{drv, key}
			d.sessions.RegisterDriver(profile.driver)
		case domain.RuntimeCodex:
			drv := agentruntime.NewCodexPersistent(binary)
			drv.Env = env
			drv.PrefixArgs = append([]string(nil), cfg.Args...)
			drv.NativeDirs = dirs
			drv.SetLifecycle(d.sup)
			drv.PTYAvailable = d.adoptEndpointPTY
			profile.driver = &codexProfileDriver{drv, key}
			d.sessions.RegisterDriver(profile.driver)
		}
	}
	return nil
}
func (d *Daemon) profileAvailable(p *loadedRuntimeProfile) bool {
	if p == nil {
		return false
	}
	if p.adapter != nil {
		return p.adapter.Available()
	}
	if available, ok := p.driver.(interface{ Available() bool }); ok {
		return available.Available()
	}
	return false
}
func (d *Daemon) detectRuntimeProfiles() []transport.RuntimeProfileInstallation {
	names := make([]string, 0, len(d.runtimeProfiles))
	for name := range d.runtimeProfiles {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]transport.RuntimeProfileInstallation, 0, len(names))
	for _, name := range names {
		p := d.runtimeProfiles[name]
		out = append(out, transport.RuntimeProfileInstallation{Name: name, Runtime: string(p.config.Runtime), Available: d.profileAvailable(p)})
	}
	return out
}
func (d *Daemon) adapterFor(row *InstanceRow) (agentruntime.Adapter, bool) {
	if row.Profile != "" {
		p := d.runtimeProfiles[row.Profile]
		if p == nil {
			return nil, false
		}
		return p.adapter, p.adapter != nil
	}
	ad, ok := d.adapters[domain.RuntimeName(row.Runtime)]
	return ad, ok
}
func (d *Daemon) sessionRuntimeFor(row *InstanceRow) domain.RuntimeName {
	if p := d.runtimeProfiles[row.Profile]; row.Profile != "" && p != nil && p.driver != nil {
		return p.driver.Name()
	}
	return domain.RuntimeName(row.Runtime)
}
func (d *Daemon) checkRuntimeProfile(row *InstanceRow, pin bool) error {
	if row.Profile == "" {
		return nil
	}
	p := d.runtimeProfiles[row.Profile]
	if p == nil || string(p.config.Runtime) != row.Runtime {
		return fmt.Errorf("runtime profile %q is not configured for this runtime", row.Profile)
	}
	if !d.profileAvailable(p) {
		return fmt.Errorf("runtime profile %q is unavailable; install its executable and reload the daemon configuration", row.Profile)
	}
	digest := p.config.Digest()
	old, found := d.state.KVGet("runtime-profile:" + row.InstanceID)
	if found && old != digest {
		return fmt.Errorf("runtime profile %q changed; start a fresh instance instead of resuming with another configuration", row.Profile)
	}
	if !found {
		if !pin || row.SessionID != "" {
			return fmt.Errorf("runtime profile %q has no verified session configuration; start a fresh instance", row.Profile)
		}
		return d.state.KVSet("runtime-profile:"+row.InstanceID, digest)
	}
	return nil
}
