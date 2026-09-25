package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// stash ui is a terminal screen for a person to browse, search, and edit
// secrets. A secret sits in the group the owner gave it with g. Without
// one, it groups by its first word (VIGI_KEY and vigi-token both go under
// VIGI). Seeing or copying a value asks for the owner password once per
// session.

const uiHelp = "↑↓ move  / search  tab complete  enter show  c copy  e edit  n new  r rename  g group  d delete  o open/close  q quit"

type uiMode int

const (
	modeBrowse uiMode = iota
	modeSearch
	modePassword
	modeInput
	modeConfirm
)

type uiRow struct {
	header string // set on a group header row
	name   string
}

type uiModel struct {
	c        *client
	names    []string
	open     map[string]bool
	groups   map[string]string // custom group per secret
	complete []string          // tab completions for the current input
	shown    map[string]string
	rows     []uiRow
	cursor   int // index into rows, always on a name row
	top      int
	height   int
	width    int
	mode     uiMode
	search   textinput.Model
	input    textinput.Model
	prompt   string
	onInput  func(m *uiModel, text string)
	onPass   func(m *uiModel)
	onYes    func(m *uiModel)
	status   string
	errState bool
}

var (
	uiHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	uiCursor = lipgloss.NewStyle().Reverse(true)
	uiDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	uiValue  = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	uiOpen   = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	uiErr    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
)

func cmdUI(args []string) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("stash ui needs a terminal")
	}
	m := &uiModel{c: newClient(), open: map[string]bool{}, groups: map[string]string{}, shown: map[string]string{}, height: 24, width: 80}
	m.search = textinput.New()
	m.search.Prompt = "/ "
	m.input = textinput.New()
	if err := m.reload(); err != nil {
		return err
	}
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func (m *uiModel) reload() error {
	var list struct {
		Secrets []string `json:"secrets"`
	}
	if err := m.c.do("GET", "/v1/secrets", nil, &list); err != nil {
		return err
	}
	var open struct {
		Open []string `json:"open"`
	}
	if err := m.c.do("GET", "/v1/open", nil, &open); err != nil {
		return err
	}
	var groups struct {
		Groups map[string]string `json:"groups"`
	}
	if err := m.c.do("GET", "/v1/groups", nil, &groups); err != nil {
		return err
	}
	m.names = list.Secrets
	m.groups = groups.Groups
	m.open = map[string]bool{}
	for _, n := range open.Open {
		m.open[n] = true
	}
	m.rebuild()
	return nil
}

// groupOf returns the first word of a name, split on _ . or -.
func groupOf(name string) string {
	if i := strings.IndexAny(name, "_.-"); i > 0 {
		return strings.ToUpper(name[:i])
	}
	return strings.ToUpper(name)
}

// groupRows sorts names into groups. A custom group wins. Otherwise a name
// goes under its first word, and a first word with one name goes to OTHER.
// Groups match without regard to case.
func groupRows(names []string, custom map[string]string) []uiRow {
	byKey := map[string][]string{}
	label := map[string]string{}
	isCustom := map[string]bool{}
	for _, n := range names {
		g, ok := custom[n]
		if !ok || g == "" {
			g = groupOf(n)
		}
		k := strings.ToUpper(g)
		byKey[k] = append(byKey[k], n)
		if ok && custom[n] != "" {
			isCustom[k] = true
			label[k] = g
		} else if _, seen := label[k]; !seen {
			label[k] = g
		}
	}
	var keys []string
	var other []string
	for k, ns := range byKey {
		if len(ns) == 1 && !isCustom[k] {
			other = append(other, ns[0])
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var rows []uiRow
	add := func(header string, ns []string) {
		sort.Slice(ns, func(i, j int) bool { return strings.ToLower(ns[i]) < strings.ToLower(ns[j]) })
		rows = append(rows, uiRow{header: fmt.Sprintf("%s (%d)", header, len(ns))})
		for _, n := range ns {
			rows = append(rows, uiRow{name: n})
		}
	}
	for _, k := range keys {
		add(label[k], byKey[k])
	}
	if len(other) > 0 {
		add("OTHER", other)
	}
	return rows
}

// completeText extends text to the longest start shared by every candidate
// that begins with it, ignoring case. If no candidate begins with it,
// candidates that contain it count instead.
func completeText(text string, candidates []string) string {
	if text == "" {
		return text
	}
	lower := strings.ToLower(text)
	var matches []string
	for _, c := range candidates {
		if strings.HasPrefix(strings.ToLower(c), lower) {
			matches = append(matches, c)
		}
	}
	if len(matches) == 0 {
		for _, c := range candidates {
			if strings.Contains(strings.ToLower(c), lower) {
				matches = append(matches, c)
			}
		}
	}
	if len(matches) == 0 {
		return text
	}
	common := matches[0]
	for _, c := range matches[1:] {
		i := 0
		for i < len(common) && i < len(c) && strings.EqualFold(common[i:i+1], c[i:i+1]) {
			i++
		}
		common = common[:i]
	}
	if len(common) > len(text) {
		return common
	}
	return text
}

// groupNames lists every group on screen, for tab completion.
func (m *uiModel) groupNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range groupRows(m.names, m.groups) {
		if r.header == "" {
			continue
		}
		g := r.header[:strings.LastIndex(r.header, " (")]
		if g != "OTHER" && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

func (m *uiModel) rebuild() {
	current := m.selected()
	q := strings.ToLower(m.search.Value())
	var names []string
	for _, n := range m.names {
		if q == "" || strings.Contains(strings.ToLower(n), q) {
			names = append(names, n)
		}
	}
	m.rows = groupRows(names, m.groups)
	m.cursor = -1
	for i, r := range m.rows {
		if r.name != "" && (m.cursor < 0 || r.name == current) {
			m.cursor = i
			if r.name == current {
				break
			}
		}
	}
}

func (m *uiModel) selected() string {
	if m.cursor >= 0 && m.cursor < len(m.rows) {
		return m.rows[m.cursor].name
	}
	return ""
}

func (m *uiModel) move(d int) {
	for i := m.cursor + d; i >= 0 && i < len(m.rows); i += d {
		if m.rows[i].name != "" {
			m.cursor = i
			return
		}
	}
}

func (m *uiModel) say(format string, a ...any) {
	m.status, m.errState = fmt.Sprintf(format, a...), false
}

func (m *uiModel) fail(err error) {
	msg := err.Error()
	if strings.Contains(msg, "token role does not allow") {
		msg += " (this needs your admin token: STASH_TOKEN=... stash ui)"
	}
	m.status, m.errState = msg, true
}

// withValue fetches a value and hands it to then. If the server wants the
// owner password, it asks for it first and tries again.
func (m *uiModel) withValue(name string, then func(m *uiModel, value string)) {
	var out struct {
		Value string `json:"value"`
	}
	err := m.c.do("GET", "/v1/secrets/"+name, nil, &out)
	if isPasswordErr(err) {
		m.askPassword(func(m *uiModel) { m.withValue(name, then) })
		return
	}
	if err != nil {
		m.failAuth(err)
		return
	}
	then(m, out.Value)
}

// withPassword runs a request that may need the owner password.
func (m *uiModel) withPassword(do func() error, done func(m *uiModel)) {
	err := do()
	if isPasswordErr(err) {
		m.askPassword(func(m *uiModel) { m.withPassword(do, done) })
		return
	}
	if err != nil {
		m.failAuth(err)
		return
	}
	done(m)
}

// failAuth reports an error. A wrong password is dropped so the next try asks again.
func (m *uiModel) failAuth(err error) {
	if strings.Contains(err.Error(), "owner password") || strings.Contains(err.Error(), "too many wrong") {
		m.c.password = ""
	}
	m.fail(err)
}

func (m *uiModel) askPassword(then func(m *uiModel)) {
	if m.c.password != "" {
		m.c.password = ""
		m.fail(errors.New("wrong owner password"))
		return
	}
	m.mode = modePassword
	m.prompt = "owner password: "
	m.input.Reset()
	m.input.EchoMode = textinput.EchoPassword
	m.input.Focus()
	m.onPass = then
}

func (m *uiModel) ask(prompt, initial string, secret bool, then func(m *uiModel, text string)) {
	m.mode = modeInput
	m.prompt = prompt
	m.input.Reset()
	m.input.SetValue(initial)
	m.input.CursorEnd()
	m.input.EchoMode = textinput.EchoNormal
	if secret {
		m.input.EchoMode = textinput.EchoPassword
	}
	m.input.Focus()
	m.onInput = then
	m.complete = nil
}

func (m *uiModel) confirm(prompt string, then func(m *uiModel)) {
	m.mode = modeConfirm
	m.prompt = prompt
	m.onYes = then
}

func (m *uiModel) exists(name string) bool {
	for _, n := range m.names {
		if n == name {
			return true
		}
	}
	return false
}

func (m *uiModel) after(msg string, a ...any) {
	if err := m.reload(); err != nil {
		m.fail(err)
		return
	}
	m.say(msg, a...)
}

func copyToClipboard(value string) error {
	for _, tool := range [][]string{{"pbcopy"}, {"wl-copy"}, {"xclip", "-selection", "clipboard"}} {
		if _, err := exec.LookPath(tool[0]); err != nil {
			continue
		}
		cmd := exec.Command(tool[0], tool[1:]...)
		cmd.Stdin = strings.NewReader(value)
		return cmd.Run()
	}
	return errors.New("no clipboard tool found")
}

func (m *uiModel) Init() tea.Cmd { return nil }

func (m *uiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height, m.width = msg.Height, msg.Width
		return m, nil
	case tea.KeyMsg:
		switch m.mode {
		case modeSearch:
			return m.updateSearch(msg)
		case modePassword, modeInput:
			return m.updateInput(msg)
		case modeConfirm:
			if msg.String() == "y" {
				m.mode = modeBrowse
				m.onYes(m)
			} else {
				m.mode = modeBrowse
				m.say("cancelled")
			}
			return m, nil
		}
		return m.updateBrowse(msg)
	}
	return m, nil
}

func (m *uiModel) updateSearch(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyTab:
		m.search.SetValue(completeText(m.search.Value(), m.names))
		m.search.CursorEnd()
		m.rebuild()
		return m, nil
	case tea.KeyEnter:
		m.mode = modeBrowse
		m.search.Blur()
		return m, nil
	case tea.KeyEsc:
		m.mode = modeBrowse
		m.search.Reset()
		m.search.Blur()
		m.rebuild()
		return m, nil
	}
	var cmd tea.Cmd
	m.search, cmd = m.search.Update(msg)
	m.rebuild()
	return m, cmd
}

func (m *uiModel) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.mode = modeBrowse
		m.input.Blur()
		m.say("cancelled")
		return m, nil
	case tea.KeyTab:
		if m.complete != nil {
			m.input.SetValue(completeText(m.input.Value(), m.complete))
			m.input.CursorEnd()
		}
		return m, nil
	case tea.KeyEnter:
		text := m.input.Value()
		m.input.Reset()
		m.input.Blur()
		wasPassword := m.mode == modePassword
		m.mode = modeBrowse
		if wasPassword {
			m.c.password = text
			m.onPass(m)
		} else {
			m.onInput(m, text)
		}
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *uiModel) updateBrowse(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	name := m.selected()
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		if m.search.Value() != "" {
			m.search.Reset()
			m.rebuild()
		}
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgup":
		for i := 0; i < m.height/2; i++ {
			m.move(-1)
		}
	case "pgdown":
		for i := 0; i < m.height/2; i++ {
			m.move(1)
		}
	case "/":
		m.mode = modeSearch
		m.search.Focus()
	case "n":
		m.ask("new secret name: ", "", false, func(m *uiModel, newName string) {
			newName = strings.TrimSpace(newName)
			if newName == "" {
				return
			}
			if m.exists(newName) {
				m.fail(fmt.Errorf("%s already exists", newName))
				return
			}
			m.ask("value for "+newName+": ", "", true, func(m *uiModel, value string) {
				if err := m.c.do("PUT", "/v1/secrets/"+newName, map[string]string{"value": value}, nil); err != nil {
					m.fail(err)
					return
				}
				m.search.Reset()
				m.after("added %s", newName)
				m.jumpTo(newName)
			})
		})
	}
	if name == "" {
		return m, nil
	}
	switch msg.String() {
	case "enter", " ":
		if _, ok := m.shown[name]; ok {
			delete(m.shown, name)
			return m, nil
		}
		m.withValue(name, func(m *uiModel, value string) {
			m.shown[name] = value
			m.say("")
		})
	case "c":
		m.withValue(name, func(m *uiModel, value string) {
			if err := copyToClipboard(value); err != nil {
				m.fail(err)
				return
			}
			m.say("copied %s", name)
		})
	case "e":
		m.ask("new value for "+name+": ", "", true, func(m *uiModel, value string) {
			if value == "" {
				m.say("empty value, nothing changed")
				return
			}
			if err := m.c.do("PUT", "/v1/secrets/"+name, map[string]string{"value": value}, nil); err != nil {
				m.fail(err)
				return
			}
			delete(m.shown, name)
			m.say("saved %s", name)
		})
	case "r":
		m.ask("rename "+name+" to: ", name, false, func(m *uiModel, newName string) {
			newName = strings.TrimSpace(newName)
			if newName == "" || newName == name {
				return
			}
			if m.exists(newName) {
				m.fail(fmt.Errorf("%s already exists", newName))
				return
			}
			m.withValue(name, func(m *uiModel, value string) {
				if err := m.c.do("PUT", "/v1/secrets/"+newName, map[string]string{"value": value}, nil); err != nil {
					m.fail(err)
					return
				}
				if g := m.groups[name]; g != "" {
					if err := m.c.do("PUT", "/v1/groups/"+newName, map[string]string{"group": g}, nil); err != nil {
						m.fail(err)
						return
					}
				}
				if err := m.c.do("DELETE", "/v1/secrets/"+name, nil, nil); err != nil {
					m.fail(err)
					return
				}
				delete(m.shown, name)
				note := ""
				if m.open[name] {
					note = " (it was open: press o to open it again)"
				}
				m.after("renamed %s to %s%s", name, newName, note)
				m.jumpTo(newName)
			})
		})
	case "g":
		m.ask("group for "+name+" (tab completes, empty clears): ", m.groups[name], false, func(m *uiModel, group string) {
			if err := m.c.do("PUT", "/v1/groups/"+name, map[string]string{"group": group}, nil); err != nil {
				m.fail(err)
				return
			}
			if strings.TrimSpace(group) == "" {
				m.after("%s back in its first-word group", name)
			} else {
				m.after("moved %s to %s", name, strings.TrimSpace(group))
			}
			m.jumpTo(name)
		})
		m.complete = m.groupNames()
	case "d":
		m.confirm(fmt.Sprintf("delete %s? y/n", name), func(m *uiModel) {
			if err := m.c.do("DELETE", "/v1/secrets/"+name, nil, nil); err != nil {
				m.fail(err)
				return
			}
			delete(m.shown, name)
			m.after("deleted %s", name)
		})
	case "o":
		method, verb := "PUT", "opened"
		if m.open[name] {
			method, verb = "DELETE", "closed"
		}
		m.withPassword(func() error { return m.c.do(method, "/v1/open/"+name, nil, nil) }, func(m *uiModel) {
			m.after("%s %s", verb, name)
		})
	}
	return m, nil
}

func (m *uiModel) jumpTo(name string) {
	for i, r := range m.rows {
		if r.name == name {
			m.cursor = i
			return
		}
	}
}

func (m *uiModel) View() string {
	var b strings.Builder
	title := fmt.Sprintf("stash  %d secrets", len(m.names))
	if len(m.open) > 0 {
		title += fmt.Sprintf("  (%d open to scripts)", len(m.open))
	}
	b.WriteString(uiHeader.Render(title) + "\n")
	if m.mode == modeSearch || m.search.Value() != "" {
		b.WriteString(m.search.View() + "\n")
	} else {
		b.WriteString("\n")
	}

	listHeight := max(3, m.height-6)
	if m.cursor < m.top {
		m.top = m.cursor
	}
	if m.cursor >= m.top+listHeight {
		m.top = m.cursor - listHeight + 1
	}
	if m.top > 0 && m.cursor >= 0 && m.rows[m.top-1].header != "" && m.cursor-m.top+1 < listHeight {
		m.top-- // keep the group header in view
	}
	end := min(len(m.rows), m.top+listHeight)
	for i := max(0, m.top); i < end; i++ {
		r := m.rows[i]
		if r.header != "" {
			b.WriteString(uiHeader.Render(r.header) + "\n")
			continue
		}
		line := "  " + r.name
		if m.open[r.name] {
			line += uiOpen.Render("  open")
		}
		if i == m.cursor {
			line = uiCursor.Render("  "+r.name) + strings.TrimPrefix(line, "  "+r.name)
		}
		if v, ok := m.shown[r.name]; ok {
			line += "  " + uiValue.Render(oneLine(v, m.width-len(r.name)-12))
		}
		b.WriteString(line + "\n")
	}
	if len(m.rows) == 0 {
		b.WriteString(uiDim.Render("  no secrets match") + "\n")
	}
	for i := end - max(0, m.top); i < listHeight; i++ {
		b.WriteString("\n")
	}

	switch m.mode {
	case modePassword, modeInput:
		b.WriteString(m.prompt + m.input.View() + "\n")
	case modeConfirm:
		b.WriteString(uiErr.Render(m.prompt) + "\n")
	default:
		if m.errState {
			b.WriteString(uiErr.Render(m.status) + "\n")
		} else {
			b.WriteString(m.status + "\n")
		}
	}
	b.WriteString(uiDim.Render(uiHelp))
	return b.String()
}

// oneLine shows a value on one line, cut to fit the screen.
func oneLine(v string, width int) string {
	v = strings.ReplaceAll(v, "\n", "⏎")
	width = max(width, 10)
	if len([]rune(v)) > width {
		return string([]rune(v)[:width-1]) + "…"
	}
	return v
}
