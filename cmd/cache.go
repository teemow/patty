package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/teemow/patty/internal/disk"
)

func init() {
	cacheCmd := &cobra.Command{
		Use:   "cache",
		Short: "Show the mirror cache",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cache, err := newCache(defaults())
			if err != nil {
				return err
			}
			entries, err := cache.Entries()
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			var total int64
			for _, e := range entries {
				total += e.Size
				_, _ = fmt.Fprintf(w, "%10s  %s  %s\n", disk.FormatSize(e.Size), e.ModTime.Format("2006-01-02 15:04"), e.Path)
			}
			_, _ = fmt.Fprintf(w, "%d mirrors, %s of %s in %s\n", len(entries), disk.FormatSize(total), disk.FormatSize(cache.MaxBytes), cache.Dir)
			return nil
		},
	}
	cacheCmd.AddCommand(&cobra.Command{
		Use:   "clean",
		Short: "Remove all mirrors from the cache",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cache, err := newCache(defaults())
			if err != nil {
				return err
			}
			n, freed, err := cache.Clean()
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed %d mirrors, freed %s\n", n, disk.FormatSize(freed))
			return nil
		},
	})
	rootCmd.AddCommand(cacheCmd)
}
