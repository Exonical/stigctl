package main

import (
	"context"
	"os"

	"github.com/Exonical/stigctl/internal/cli"
	"github.com/charmbracelet/fang"
)

func main() {
	if err := fang.Execute(context.Background(), cli.NewRootCommand()); err != nil {
		os.Exit(1)
	}
}
