package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	"github.com/aburaihan-dev/gowalld/internal/firewall"
)

// printRules renders rules per the global -o/--output flag: a human table
// by default, or machine-readable json/yaml for scripting.
func printRules(rules []firewall.Rule) error {
	switch flagOutput {
	case "json":
		return printJSON(rules)
	case "yaml":
		return printYAML(rules)
	default:
		return printRulesTable(rules)
	}
}

func printRulesTable(rules []firewall.Rule) error {
	if len(rules) == 0 {
		fmt.Println("No rules.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tACTION\tDIR\tPORT\tPROTO\tSOURCE\tZONE\tCOMMENT")
	for _, r := range rules {
		target := r.Port
		if r.ServiceName != "" {
			target = r.ServiceName
		}
		source := r.Source
		if source == "" {
			source = "any"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.ID, r.Action, r.Direction, target, r.Protocol, source, r.Zone, r.Comment)
	}
	return w.Flush()
}

func printPlan(plan *firewall.RestorePlan) error {
	switch flagOutput {
	case "json":
		return printJSON(plan)
	case "yaml":
		return printYAML(plan)
	default:
		fmt.Printf("To add (%d):\n", len(plan.ToAdd))
		if err := printRulesTable(plan.ToAdd); err != nil {
			return err
		}
		fmt.Printf("\nTo remove (%d):\n", len(plan.ToRemove))
		if err := printRulesTable(plan.ToRemove); err != nil {
			return err
		}
		fmt.Printf("\nUnchanged: %d rule(s)\n", len(plan.Unchanged))
		return nil
	}
}

func printStatus(status *firewall.Status) error {
	switch flagOutput {
	case "json":
		return printJSON(status)
	case "yaml":
		return printYAML(status)
	default:
		state := "inactive"
		if status.Enabled {
			state = "active"
		}
		fmt.Printf("Backend:        %s\n", status.Backend)
		fmt.Printf("Status:         %s\n", state)
		fmt.Printf("Default in:     %s\n", status.DefaultIn)
		fmt.Printf("Default out:    %s\n", status.DefaultOut)
		if status.ActiveZone != "" {
			fmt.Printf("Active zone:    %s\n", status.ActiveZone)
		}
		if flagVerbose && status.Raw != "" {
			fmt.Println("\n--- raw backend output ---")
			fmt.Println(status.Raw)
		}
		return nil
	}
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printYAML(v any) error {
	enc := yaml.NewEncoder(os.Stdout)
	defer enc.Close()
	return enc.Encode(v)
}
