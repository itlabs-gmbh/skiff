package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/sovyn-eu/skiff/internal/app"
	"github.com/sovyn-eu/skiff/internal/config"
	"github.com/sovyn-eu/skiff/internal/profile"
	"github.com/sovyn-eu/skiff/internal/vm"
)

func newNewCmd(get func() *app.App) *cobra.Command {
	spec := vm.Spec{}
	var asJSON bool
	var flags profileFlags
	cmd := &cobra.Command{
		Use:   "new [name]",
		Short: "Create and boot a VM (needs at least 1 GiB of memory)",
		Long: `new creates a VM. A ./` + profile.RepoFile + ` file and the machine default
~/.skiff/profile.toml, when present, size it, grant its capabilities, install
tools and skills and configure the agents inside; flags given here win over
the profile's values.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				spec.Name = args[0]
			}
			prof, err := flags.resolve(get())
			if err != nil {
				return err
			}
			spec = applyMachine(cmd, spec, prof.Machine)
			info, err := get().NewVM(cmd.Context(), spec, &prof)
			var pe *app.ProfileError
			if errors.As(err, &pe) {
				return fmt.Errorf("%w\n  %s is running without its profile and grants; finish it with: %s",
					err, pe.Name, flags.applyRetry(pe.Name, spec.Grants))
			}
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(cmd, info)
			}
			return nil
		},
	}
	addJSONFlag(cmd, &asJSON)
	cmd.Flags().IntVar(&spec.VCPUs, "vcpus", config.DefaultVCPUs, "number of vCPUs")
	cmd.Flags().IntVar(&spec.MemMiB, "mem", config.DefaultMemMiB, "memory in MiB")
	cmd.Flags().StringArrayVarP(&spec.Forwards, "port", "p", nil, "forward localhost:[HOST:]GUEST to the VM (repeatable)")
	cmd.Flags().StringArrayVar(&spec.Grants, "grant", nil, "grant a capability right away, e.g. claude or github (repeatable)")
	cmd.Flags().StringVar(&spec.Owner, "owner", "", "label the tool or person managing the VM; owned VMs can be collected by 'skiff gc'")
	cmd.Flags().StringVar(&spec.Slot, "slot", "", "the VM's position in its owner's pool, e.g. 3 (needs --owner)")
	flags.add(cmd)
	return cmd
}

func newForwardCmd(get func() *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "forward NAME [[HOST:]GUEST...]",
		Short: "Expose VM ports on localhost (lists forwards when no ports are given)",
		Example: "  skiff forward web 8080        # localhost:8080 -> web:8080\n" +
			"  skiff forward web 3000:80     # localhost:3000 -> web:80",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			info, err := get().Forward(cmd.Context(), args[0], args[1:])
			if err != nil {
				return err
			}
			if len(args) == 1 {
				printForwards(cmd, info)
			}
			return nil
		},
	}
}

func newUnforwardCmd(get func() *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "unforward NAME HOSTPORT...",
		Short: "Remove port forwards by host port",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ports := make([]int, 0, len(args)-1)
			for _, p := range args[1:] {
				port, err := strconv.Atoi(p)
				if err != nil {
					return fmt.Errorf("invalid port %q", p)
				}
				ports = append(ports, port)
			}
			_, err := get().Unforward(cmd.Context(), args[0], ports)
			return err
		},
	}
}

func printForwards(cmd *cobra.Command, info app.VMInfo) {
	if len(info.Forwards) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "%s has no port forwards\n", info.Name)
		return
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LOCAL\tGUEST\tSTATE")
	for _, f := range info.Forwards {
		fmt.Fprintf(w, "localhost:%d\t%s:%d\t%s\n", f.Host, info.Name, f.Guest, f.State)
	}
	_ = w.Flush()
}

func forwardLabels(info app.VMInfo) string {
	if len(info.Forwards) == 0 {
		return "-"
	}
	labels := make([]string, 0, len(info.Forwards))
	for _, f := range info.Forwards {
		labels = append(labels, f.Label())
	}
	return strings.Join(labels, ",")
}

func newRmCmd(get func() *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "rm NAME",
		Short: "Stop and delete a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return get().RemoveVM(cmd.Context(), args[0])
		},
	}
}

func newStartCmd(get func() *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "start NAME",
		Short: "Boot a stopped VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := get().StartVM(cmd.Context(), args[0])
			return err
		},
	}
}

func newStopCmd(get func() *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "stop NAME",
		Short: "Shut a VM down, keeping its disk",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := get().StopVM(cmd.Context(), args[0])
			return err
		},
	}
}

func newLsCmd(get func() *app.App) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List VMs",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			vms, err := get().ListVMs(cmd.Context())
			if err != nil {
				return err
			}
			if asJSON {
				if vms == nil {
					vms = []app.VMInfo{} // print [] rather than null
				}
				return writeJSON(cmd, vms)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSTATE\tIP\tVCPUS\tMEM\tPORTS\tGRANTS\tOWNER\tAGE\tSSH")
			now := time.Now()
			for _, v := range vms {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%dM\t%s\t%s\t%s\t%s\t%s\n",
					v.Name, v.State, v.IP, v.VCPUs, v.MemMiB, forwardLabels(v), grantLabels(v),
					ownerLabel(v), ageLabel(v, now), sshHint(v))
			}
			return w.Flush()
		},
	}
	addJSONFlag(cmd, &asJSON)
	return cmd
}

func newInspectCmd(get func() *app.App) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "inspect NAME",
		Short: "Show the details of a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			info, err := get().InspectVM(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(cmd, info)
			}
			return printVM(cmd, info)
		},
	}
	addJSONFlag(cmd, &asJSON)
	return cmd
}

func printVM(cmd *cobra.Command, v app.VMInfo) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Name:\t%s\n", v.Name)
	fmt.Fprintf(w, "State:\t%s\n", v.State)
	fmt.Fprintf(w, "IP:\t%s\n", v.IP)
	fmt.Fprintf(w, "vCPUs:\t%d\n", v.VCPUs)
	fmt.Fprintf(w, "Memory:\t%dM\n", v.MemMiB)
	fmt.Fprintf(w, "Ports:\t%s\n", forwardLabels(v))
	fmt.Fprintf(w, "Grants:\t%s\n", grantLabels(v))
	fmt.Fprintf(w, "Owner:\t%s\n", dashIfEmpty(v.Owner))
	fmt.Fprintf(w, "Slot:\t%s\n", dashIfEmpty(v.Slot))
	fmt.Fprintf(w, "Created:\t%s\n", createdLabel(v, time.Now()))
	fmt.Fprintf(w, "SSH:\t%s\n", sshHint(v))
	return w.Flush()
}

// ownerLabel renders owner and slot as "owner/slot" for the ls table.
func ownerLabel(v app.VMInfo) string {
	if v.Slot != "" {
		return v.Owner + "/" + v.Slot
	}
	return dashIfEmpty(v.Owner)
}

func ageLabel(v app.VMInfo, now time.Time) string {
	if v.CreatedAt == nil {
		return "-"
	}
	return app.HumanAge(now.Sub(*v.CreatedAt))
}

func createdLabel(v app.VMInfo, now time.Time) string {
	if v.CreatedAt == nil {
		return "-"
	}
	return v.CreatedAt.Local().Format(time.RFC3339) + " (" + ageLabel(v, now) + " ago)"
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func sshHint(v app.VMInfo) string {
	return "ssh " + v.Name + "." + config.Instance
}

func newSSHCmd(get func() *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh NAME [command...]",
		Short: "Open a shell in a VM (or run a command)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return get().SSH(cmd.Context(), args[0], remoteArgs(args))
		},
	}
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func newTunnelCmd(get func() *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "tunnel NAME",
		Short: "Serve a VM's broker without an interactive session",
		Long: `tunnel holds the broker forward into NAME until it is interrupted or NAME
stops, reconnecting when the connection drops. Use it when the guest is
reached by something other than 'skiff ssh', e.g. an editor or agent
runner with its own ssh session. 'skiff ssh NAME' keeps working alongside.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return get().Tunnel(cmd.Context(), args[0])
		},
	}
}

func newExecCmd(get func() *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec NAME -- command [arg...]",
		Short: "Run a command in a VM with its arguments passed verbatim",
		Long: `exec runs a command in a VM with every argument quoted, so the guest
receives exactly the argument vector given here. Unlike 'skiff ssh NAME cmd',
no word is re-split or expanded by the guest shell; scripts and plugins can pass
untrusted strings safely. Stdin, stdout, stderr and the exit status are
forwarded like with ssh.`,
		Example: "  skiff exec dev -- sh -c 'echo $HOME | wc -c'\n" +
			"  skiff exec dev -- git commit -m \"it's done\"",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return get().Exec(cmd.Context(), args[0], remoteArgs(args))
		},
	}
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// remoteArgs returns everything after NAME. A single leading "--" is
// skiff's own separator (`skiff ssh NAME -- cmd`); a later one belongs
// to the remote command.
func remoteArgs(args []string) []string {
	remote := args[1:]
	if len(remote) > 0 && remote[0] == "--" {
		return remote[1:]
	}
	return remote
}
