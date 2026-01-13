package main

import (
	"fmt"
	"keyopol-app/internal/runner"
	"keyopol-app/internal/ui"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "run":
			runner.Run()
			return
		case "get":
			runner.Get()
			return
		}
	}

	p := tea.NewProgram(ui.InitialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
