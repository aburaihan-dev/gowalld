package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aburaihan-dev/gowalld/internal/backup"
)

var (
	backupOutputDir string
	backupFile      string
	backupComment   string
)

var backupCmd = &cobra.Command{
	Use:   "backup [name]",
	Short: "Snapshot the current firewall configuration to a file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := newService(cmd.Context())
		if err != nil {
			return err
		}
		snap, err := svc.Snapshot(cmd.Context())
		if err != nil {
			return err
		}
		if backupComment != "" {
			snap.Metadata.Comment = backupComment
		}

		name := backupFile
		if name == "" && len(args) == 1 {
			name = args[0]
		}
		dir := backupOutputDir
		if dir == "" && loadedConfig != nil {
			dir = loadedConfig.BackupDir
		}
		path, err := backup.Write(snap, dir, name)
		if err != nil {
			return err
		}
		fmt.Printf("Backup written to %s (%d rules)\n", path, len(snap.Rules))
		return nil
	},
}

func init() {
	backupCmd.Flags().StringVar(&backupOutputDir, "output-dir", "", "directory to write the backup in (default: "+backup.DefaultDir+")")
	backupCmd.Flags().StringVar(&backupFile, "file", "", "explicit backup file name (overrides the positional name argument)")
	backupCmd.Flags().StringVar(&backupComment, "comment", "", "a note to attach to this backup")
}
