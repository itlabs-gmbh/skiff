package cli

import (
	"github.com/spf13/cobra"

	"github.com/sovyn-eu/skiff/internal/app"
	"github.com/sovyn-eu/skiff/internal/profile"
	"github.com/sovyn-eu/skiff/internal/shquote"
	"github.com/sovyn-eu/skiff/internal/vm"
)

// profileFlags selects the repository profile file: --profile names one,
// --no-profile ignores it; the machine default always applies.
type profileFlags struct {
	path  string
	skip  bool
	trust bool
}

func (f *profileFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.path, "profile", "", "profile file to use instead of ./"+profile.RepoFile)
	cmd.Flags().BoolVar(&f.skip, "no-profile", false, "ignore ./"+profile.RepoFile+" (the machine default still applies)")
	cmd.Flags().BoolVar(&f.trust, "trust", false, "trust the repository's profile file as it is now (like 'skiff profile trust')")
}

// resolve returns the merged profile the flags select, for a command that
// acts on it: the repository file must be trusted.
func (f profileFlags) resolve(a *app.App) (profile.Profile, error) {
	repoFile, explicit := f.selection()
	return a.ResolveTrustedProfile(repoFile, explicit, f.trust)
}

// applyMachine takes the profile's size and ports for everything the user
// did not set on the command line.
func applyMachine(cmd *cobra.Command, spec vm.Spec, m profile.Machine) vm.Spec {
	out := spec
	if !cmd.Flags().Changed("vcpus") && m.VCPUs > 0 {
		out.VCPUs = m.VCPUs
	}
	if !cmd.Flags().Changed("mem") && m.MemMiB > 0 {
		out.MemMiB = m.MemMiB
	}
	out.Forwards = unionStrings(spec.Forwards, m.Ports)
	return out
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string(nil), a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func newApplyCmd(get func() *app.App) *cobra.Command {
	var flags profileFlags
	var setup, clear bool
	var grants []string
	cmd := &cobra.Command{
		Use:   "apply NAME",
		Short: "Apply the profile (./" + profile.RepoFile + " and the machine default) to a running VM",
		Long: `apply grants the profile's capabilities and writes the agent configuration
it declares (plugins, MCP servers, settings) into the guest, replacing what an
earlier profile wrote. Grants are only added; revoke by hand what the profile
no longer lists; --grant adds capabilities on top of the profile's, as on
'skiff new'. With --setup the packages, tools, skills and setup script are
installed again first, as 'skiff new' does. --clear removes the profile's
configuration from the VM instead and forgets the profile; grants stay.`,
		Example: "  skiff apply agent1\n  skiff apply agent1 --setup --grant github\n  skiff apply agent1 --profile ../other/.skiff\n  skiff apply agent1 --clear",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if clear {
				return get().ProfileClear(cmd.Context(), args[0])
			}
			prof, err := flags.resolve(get())
			if err != nil {
				return err
			}
			_, err = get().Apply(cmd.Context(), args[0], prof, grants, setup)
			return err
		},
	}
	flags.add(cmd)
	cmd.Flags().BoolVar(&setup, "setup", false, "run the profile's installs (packages, tools, skills, setup) again")
	cmd.Flags().BoolVar(&clear, "clear", false, "remove the profile's configuration from the VM and forget the profile (grants stay)")
	cmd.Flags().StringArrayVar(&grants, "grant", nil, "also grant this capability, e.g. github (repeatable)")
	cmd.MarkFlagsMutuallyExclusive("clear", "setup")
	cmd.MarkFlagsMutuallyExclusive("clear", "grant")
	cmd.MarkFlagsMutuallyExclusive("clear", "profile")
	return cmd
}

func newProfileCmd(get func() *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage profiles (what a VM needs: size, grants, tools, skills, agent plugins and MCPs)",
		Long: `A profile is a TOML file. ~/.skiff/profile.toml is the machine default and
applies to every VM; a .skiff file in a repository adds what that repository
needs. 'skiff new' merges both and 'skiff apply' brings a running VM up to
date. Lists are joined, tables merged key by key, and a value in .skiff wins.`,
	}
	var showFlags profileFlags
	var vmName string
	var render bool
	show := &cobra.Command{
		Use:   "show",
		Short: "Print the merged profile, or the one applied to a VM with --vm",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			repoFile, explicit := showFlags.selection()
			return get().ProfileShow(repoFile, explicit, vmName, render)
		},
	}
	showFlags.add(show)
	show.Flags().StringVar(&vmName, "vm", "", "show the profile applied to this VM")
	show.Flags().BoolVar(&render, "render", false, "also show the guest configuration and setup script")

	var global bool
	initCmd := &cobra.Command{
		Use:   "init [FILE]",
		Short: "Write a commented skeleton as ./" + profile.RepoFile + " (or the machine default with --global)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := profile.RepoFile
			if len(args) == 1 {
				path = args[0]
			}
			return get().ProfileInit(path, global)
		},
	}
	initCmd.Flags().BoolVar(&global, "global", false, "write ~/.skiff/profile.toml instead")

	trust := &cobra.Command{
		Use:   "trust [FILE]",
		Short: "Trust a repository's profile file as it is now, so 'new' and 'apply' use it",
		Long: `A profile in a repository chooses grants, forwards ports and runs its setup
as root in the VM, so skiff only uses it once you have read it. trust records
the file's content; after an edit it has to be trusted again. The machine
default needs no trust.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := profile.RepoFile
			if len(args) == 1 {
				path = args[0]
			}
			return get().ProfileTrust(path)
		},
	}

	lint := &cobra.Command{
		Use:   "lint [FILE]",
		Short: "Validate a profile file, or the machine default and ./" + profile.RepoFile + " together",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) == 1 {
				path = args[0]
			}
			return get().ProfileLint(path, profile.RepoFile)
		},
	}
	cmd.AddCommand(show, initCmd, lint, trust)
	return cmd
}

// applyRetry is the `skiff apply` that finishes a VM whose profile failed
// during `skiff new`: it selects the same profile and passes the --grant
// capabilities again, which Apply had not stored yet. --trust is left out
// because `new` already recorded the trust.
func (f profileFlags) applyRetry(name string, grants []string) string {
	cmd := "skiff apply " + shquote.Quote(name) + " --setup"
	switch {
	case f.skip:
		cmd += " --no-profile"
	case f.path != "":
		cmd += " --profile " + shquote.Quote(f.path)
	}
	for _, g := range grants {
		cmd += " --grant " + shquote.Quote(g)
	}
	return cmd
}

// selection reports the repository file the flags name and whether it was
// named explicitly.
func (f profileFlags) selection() (string, bool) {
	if f.skip {
		return "", false
	}
	if f.path != "" {
		return f.path, true
	}
	return profile.RepoFile, false
}
