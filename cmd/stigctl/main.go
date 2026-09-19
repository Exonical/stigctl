package main

import (
	"context"
	"os"

	"charm.land/fang/v2"
	"github.com/Exonical/stigctl/internal/cli"
)

func main() {
	if err := fang.Execute(context.Background(), cli.NewRootCommand()); err != nil {
		os.Exit(1)
	}
}
