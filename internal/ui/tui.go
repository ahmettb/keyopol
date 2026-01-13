package ui

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"keyopol-app/internal/crypto"
	"keyopol-app/internal/store"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type inputMode int

const (
	modeNormal inputMode = iota
	modeAddProject
	modeEditProject
	modeAddSecretKey
	modeAddSecretValue
	modeEditSecret
)

var (
	colorBg        = lipgloss.Color("#191724")
	colorPanel     = lipgloss.Color("#1f1d2e")
	colorText      = lipgloss.Color("#e0def4")
	colorSubtle    = lipgloss.Color("#6e6a86")
	colorAccent    = lipgloss.Color("#ebbcba")
	colorSecondary = lipgloss.Color("#9ccfd8")
	colorGold      = lipgloss.Color("#f6c177")

	styleLogoBox = lipgloss.NewStyle().
			Background(colorAccent).
			Foreground(colorBg).
			Bold(true).
			Padding(0, 3).
			MarginBottom(1)

	styleLogoText = lipgloss.NewStyle().
			Bold(true).
			Background(colorAccent).
			Foreground(colorBg)

	styleBoxActive = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorAccent).
			Padding(0, 1)

	styleBoxInactive = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorSubtle).
				Padding(0, 1)

	styleItemActive = lipgloss.NewStyle().
			Foreground(colorBg).
			Background(colorSecondary).
			Bold(true).
			Padding(0, 1)

	styleItemNormal = lipgloss.NewStyle().
			Foreground(colorText).
			Padding(0, 1)

	styleStatusMsg = lipgloss.NewStyle().
			Foreground(colorGold).
			Bold(true).
			Italic(true)

	styleFooter = lipgloss.NewStyle().
			Foreground(colorSubtle).
			PaddingTop(1)

	styleInputBox = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(colorAccent).
			Padding(1, 1).
			Width(40).
			Align(lipgloss.Center).
			Background(colorPanel)
)

type clearStatusMsg struct{}

type Model struct {
	db        *sql.DB
	masterKey string

	width, height int

	projects []string
	secrets  []store.Secret

	projectI int
	secretI  int
	focus    string

	mode      inputMode
	textInput textinput.Model
	tempKey   string

	statusMsg string
}

func InitialModel() Model {
	mKey := crypto.GetMasterKey()
	db := store.InitDB()
	projects := store.GetProjects(db)

	ti := textinput.New()
	ti.Cursor.Style = lipgloss.NewStyle().Foreground(colorAccent)
	ti.Prompt = "→ "
	ti.CharLimit = 60

	m := Model{
		db:        db,
		masterKey: mKey,
		projects:  projects,
		projectI:  0,
		focus:     "projects",
		mode:      modeNormal,
		textInput: ti,
		statusMsg: "",
	}

	if len(m.projects) > 0 {
		m.secrets = store.GetSecrets(db, m.projects[0], mKey)
	}

	return m
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg.(type) {
	case clearStatusMsg:
		m.statusMsg = ""
		return m, nil
	}

	if m.mode != modeNormal {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc":
				m.mode = modeNormal
				m.textInput.Blur()
				return m, nil
			case "enter":
				return m.handleInputSubmission()
			}
		}
		m.textInput, cmd = m.textInput.Update(msg)
		return m, cmd
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "Q", "ctrl+c":
			return m, tea.Quit

		case "tab":
			if m.focus == "projects" {
				m.focus = "secrets"
			} else {
				m.focus = "projects"
			}

		case "up", "k", "K":
			m.moveCursor(-1)
		case "down", "j", "J":
			m.moveCursor(1)

		case " ":
			if m.focus == "secrets" && len(m.secrets) > 0 {
				m.secrets[m.secretI].IsVisible = !m.secrets[m.secretI].IsVisible
			}

		case "c", "C":
			if m.focus == "secrets" && len(m.secrets) > 0 {
				val := m.secrets[m.secretI].ValueDec
				err := clipboard.WriteAll(val)
				if err == nil {
					m.statusMsg = "COPIED TO CLIPBOARD!"
					return m, tea.Tick(time.Second*2, func(_ time.Time) tea.Msg {
						return clearStatusMsg{}
					})
				}
			}

		case "a", "A":
			m.initAdd()
		case "d", "D":
			m.handleDelete()
		case "e", "E":
			m.initEdit()
		}
	}
	return m, nil
}

func (m *Model) moveCursor(dir int) {
	if m.focus == "projects" {
		if len(m.projects) == 0 {
			return
		}
		m.projectI += dir
		if m.projectI < 0 {
			m.projectI = 0
		}
		if m.projectI >= len(m.projects) {
			m.projectI = len(m.projects) - 1
		}
		m.refreshSecrets()
	} else {
		if len(m.secrets) == 0 {
			return
		}
		m.secretI += dir
		if m.secretI < 0 {
			m.secretI = 0
		}
		if m.secretI >= len(m.secrets) {
			m.secretI = len(m.secrets) - 1
		}
	}
}

func (m *Model) initAdd() {
	m.textInput.Reset()
	m.textInput.Focus()
	if m.focus == "projects" {
		m.mode = modeAddProject
		m.textInput.Placeholder = "Project Name..."
	} else if len(m.projects) > 0 {
		m.mode = modeAddSecretKey
		m.textInput.Placeholder = "KEY_NAME..."
	}
}

func (m *Model) initEdit() {
	m.textInput.Reset()
	m.textInput.Focus()
	if m.focus == "projects" && len(m.projects) > 0 {
		m.mode = modeEditProject
		m.tempKey = m.projects[m.projectI]
		m.textInput.SetValue(m.projects[m.projectI])
	} else if m.focus == "secrets" && len(m.secrets) > 0 {
		m.mode = modeEditSecret
		m.tempKey = m.secrets[m.secretI].Key
		m.textInput.Placeholder = "New Value..."
	}
}

func (m Model) handleInputSubmission() (Model, tea.Cmd) {
	val := strings.TrimSpace(m.textInput.Value())

	switch m.mode {
	case modeAddProject:
		if val != "" {
			store.CreateProject(m.db, val)
			m.projects = store.GetProjects(m.db)
			m.projectI = len(m.projects) - 1
			m.refreshSecrets()
		}
		m.mode = modeNormal

	case modeEditProject:
		if val != "" {
			store.UpdateProject(m.db, m.tempKey, val)
			m.projects = store.GetProjects(m.db)
			m.refreshSecrets()
		}
		m.mode = modeNormal

	case modeAddSecretKey:
		if val != "" {
			m.tempKey = strings.ToUpper(val)
			m.mode = modeAddSecretValue
			m.textInput.Reset()
			m.textInput.Placeholder = "Value..."
			return m, nil
		}
		m.mode = modeNormal

	case modeAddSecretValue:
		if m.tempKey != "" {
			store.AddSecret(m.db, m.projects[m.projectI], m.tempKey, val, m.masterKey)
			m.refreshSecrets()
		}
		m.mode = modeNormal

	case modeEditSecret:
		store.UpdateSecret(m.db, m.projects[m.projectI], m.tempKey, val, m.masterKey)
		m.refreshSecrets()
		m.mode = modeNormal
	}

	m.textInput.Blur()
	return m, nil
}

func (m *Model) handleDelete() {
	if m.focus == "projects" && len(m.projects) > 0 {
		store.DeleteProject(m.db, m.projects[m.projectI])
		m.projects = store.GetProjects(m.db)
		if m.projectI >= len(m.projects) {
			m.projectI = len(m.projects) - 1
		}
		if m.projectI < 0 {
			m.projectI = 0
		}
		m.refreshSecrets()
	} else if m.focus == "secrets" && len(m.secrets) > 0 {
		store.DeleteSecret(m.db, m.projects[m.projectI], m.secrets[m.secretI].Key)
		m.refreshSecrets()
	}
}

func (m *Model) refreshSecrets() {
	if len(m.projects) > 0 && m.projectI < len(m.projects) {
		m.secrets = store.GetSecrets(m.db, m.projects[m.projectI], m.masterKey)
		m.secretI = 0
	} else {
		m.secrets = []store.Secret{}
	}
}

func (m Model) View() string {
	if m.width == 0 {
		return ""
	}

	header := lipgloss.JoinHorizontal(lipgloss.Center,
		styleLogoBox.Render(" K E Y O P O L "),
		"   ",
		styleStatusMsg.Render(m.statusMsg),
	)
	footer := m.renderFooter()

	availHeight := m.height - lipgloss.Height(header) - lipgloss.Height(footer) - 2
	if availHeight < 5 {
		availHeight = 5
	}

	leftW := int(float64(m.width) * 0.3)
	rightW := m.width - leftW - 4

	leftView := m.renderProjectsBox(leftW, availHeight)
	rightView := m.renderSecretsBox(rightW, availHeight)

	mainContent := lipgloss.JoinHorizontal(lipgloss.Top, leftView, rightView)
	fullView := lipgloss.JoinVertical(lipgloss.Left, header, mainContent, footer)

	if m.mode != modeNormal {
		return m.renderModal()
	}

	return fullView
}

func (m Model) renderProjectsBox(w, h int) string {
	var b strings.Builder

	title := "PROJECTS"
	b.WriteString(lipgloss.NewStyle().Foreground(colorSubtle).Bold(true).Render(title) + "\n\n")

	if len(m.projects) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorSubtle).Italic(true).Render("empty"))
	}

	for i, p := range m.projects {
		if len(p) > w-4 {
			p = p[:w-4] + ".."
		}

		if i == m.projectI {
			b.WriteString(styleItemActive.Width(w-4).Render(p) + "\n")
		} else {
			b.WriteString(styleItemNormal.Render(p) + "\n")
		}
	}

	style := styleBoxInactive
	if m.focus == "projects" {
		style = styleBoxActive
	}

	return style.Width(w).Height(h).Render(b.String())
}

func (m Model) renderSecretsBox(w, h int) string {
	var b strings.Builder

	cols := fmt.Sprintf("%-20s %-20s %-12s", "KEY", "VALUE", "UPDATED")
	b.WriteString(lipgloss.NewStyle().Foreground(colorSubtle).Bold(true).Render(cols) + "\n\n")

	if len(m.secrets) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorSubtle).Italic(true).Render("no secrets"))
	}

	for i, s := range m.secrets {
		if s.Key == "_init_" {
			continue
		}

		k := s.Key
		v := "••••••"
		if s.IsVisible {
			v = s.ValueDec
		}

		if len(k) > 18 {
			k = k[:16] + ".."
		}
		if len(v) > 18 {
			v = v[:16] + ".."
		}

		line := fmt.Sprintf("%-20s %-20s %-12s", k, v, s.UpdatedAt)

		if i == m.secretI {
			b.WriteString(styleItemActive.Width(w-4).Render(line) + "\n")
		} else {
			b.WriteString(styleItemNormal.Render(line) + "\n")
		}
	}

	style := styleBoxInactive
	if m.focus == "secrets" {
		style = styleBoxActive
	}

	return style.Width(w).Height(h).Render(b.String())
}

func (m Model) renderModal() string {
	title := "INPUT"
	icon := "✎"

	switch m.mode {
	case modeAddProject:
		title = "NEW PROJECT"
	case modeEditProject:
		title = "RENAME PROJECT"
	case modeAddSecretKey:
		title = "NEW KEY"
	case modeAddSecretValue:
		title = "SECRET VALUE"
	case modeEditSecret:
		title = "EDIT VALUE"
	}

	content := lipgloss.JoinVertical(lipgloss.Center,
		lipgloss.NewStyle().Foreground(colorAccent).Bold(true).Render(icon+" "+title),
		"\n",
		m.textInput.View(),
		"\n",
		lipgloss.NewStyle().Foreground(colorSubtle).Italic(true).Render("Esc: Cancel • Enter: Save"),
	)

	box := styleInputBox.Render(content)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

func (m Model) renderFooter() string {
	var cmds []string

	hl := lipgloss.NewStyle().Foreground(colorText).Bold(true)
	dim := lipgloss.NewStyle().Foreground(colorSubtle)

	cmds = append(cmds, hl.Render("TAB")+dim.Render(" switch"))

	if m.focus == "projects" {
		cmds = append(cmds, hl.Render("A")+dim.Render(" add"))
		cmds = append(cmds, hl.Render("E")+dim.Render(" rename"))
		cmds = append(cmds, hl.Render("D")+dim.Render(" delete"))
	} else {
		cmds = append(cmds, hl.Render("C")+dim.Render(" copy"))
		cmds = append(cmds, hl.Render("A")+dim.Render(" add"))
		cmds = append(cmds, hl.Render("E")+dim.Render(" edit"))
		cmds = append(cmds, hl.Render("D")+dim.Render(" del"))
		cmds = append(cmds, hl.Render("SPC")+dim.Render(" show"))
	}

	cmds = append(cmds, hl.Render("Q")+dim.Render(" quit"))

	return styleFooter.Width(m.width).Align(lipgloss.Center).Render(strings.Join(cmds, dim.Render("  |  ")))
}
