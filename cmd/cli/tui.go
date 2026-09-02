package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// requestResult holds the values collected by the interactive wizard.
type requestResult struct {
	canceled bool
	Username string
	Target   string
	Duration string
	Reason   string
}

// Canceled reports whether the user aborted the wizard before finishing.
func (r requestResult) Canceled() bool { return r.canceled }

// Wizard steps.
const (
	stepUsername = iota
	stepHost
	stepDuration
	stepReason
	stepCount
)

// durationPresets are the common lease durations offered as quick choices.
var durationPresets = []string{"15m", "30m", "1h", "2h", "4h", "8h", "Custom..."}

// stepTitles are rendered as the heading of each wizard step.
var stepTitles = [stepCount]string{
	"Username",
	"Target host",
	"Duration",
	"Reason",
}

// stepHints are shorter field labels shown next to the interactive area.
var stepHints = [stepCount]string{
	"who gets access?",
	"which server?",
	"how long?",
	"why?",
}

// textInput is a minimal single-line text field with a moving cursor.
type textInput struct {
	cur string
	pos int
}

// insert adds a rune at the cursor position.
func (t *textInput) insert(r rune) {
	runes := []rune(t.cur)
	runes = append(runes, 0)
	copy(runes[t.pos+1:], runes[t.pos:])
	runes[t.pos] = r
	t.cur = string(runes)
	t.pos++
}

// backspace removes the rune preceding the cursor.
func (t *textInput) backspace() {
	if t.pos > 0 {
		runes := []rune(t.cur)
		runes = append(runes[:t.pos-1], runes[t.pos:]...)
		t.cur = string(runes)
		t.pos--
	}
}

func (t *textInput) left() {
	if t.pos > 0 {
		t.pos--
	}
}

func (t *textInput) right() {
	if t.pos < len([]rune(t.cur)) {
		t.pos++
	}
}

// durationSelect is a single-selection list for the duration step.
type durationSelect struct {
	options []string
	index   int
}

func (s *durationSelect) up() {
	if s.index > 0 {
		s.index--
	}
}

func (s *durationSelect) down() {
	if s.index < len(s.options)-1 {
		s.index++
	}
}

func (s *durationSelect) selected() string { return s.options[s.index] }
func (s *durationSelect) isCustom() bool   { return s.options[s.index] == "Custom..." }

// wizardStyle groups the Lipgloss styles used across the wizard rendering.
type wizardStyle struct {
	accent   lipgloss.Style
	title    lipgloss.Style
	field    lipgloss.Style
	focused  lipgloss.Style
	cursorBg lipgloss.Style
	box      lipgloss.Style
	selected lipgloss.Style
	option   lipgloss.Style
	help     lipgloss.Style
	check    lipgloss.Style
}

// makeWizardStyle returns the default Lipgloss styles: a subtle, bordered look
// with a single accent colour for the active selection.
func makeWizardStyle() wizardStyle {
	accent := lipgloss.Color("#7c5cff")
	return wizardStyle{
		accent:   lipgloss.NewStyle().Foreground(accent).Bold(true),
		title:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#f0f0f0")).Padding(0, 1),
		field:    lipgloss.NewStyle().Foreground(lipgloss.Color("#b8b8c0")),
		focused:  lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff")),
		cursorBg: lipgloss.NewStyle().Background(lipgloss.Color("#3a3a55")).Foreground(lipgloss.Color("#ffffff")),
		box:      lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#4a4a60")).Padding(0, 1),
		selected: lipgloss.NewStyle().Foreground(accent).Bold(true),
		option:   lipgloss.NewStyle().Foreground(lipgloss.Color("#b8b8c0")),
		help:     lipgloss.NewStyle().Foreground(lipgloss.Color("#777788")),
		check:    lipgloss.NewStyle().Foreground(lipgloss.Color("#3fb950")),
	}
}

// wizard is a bubbletea.Model implementing a step-by-step request form.
type wizard struct {
	step      int
	styles    wizardStyle
	user      textInput
	host      textInput
	reason    textInput
	duration  durationSelect
	durCustom textInput // active when the user picks "Custom..."
	val       requestResult
	done      bool
}

// newWizard seeds the wizard with defaults: defaultUser (may be empty) and the
// "*" wildcard target. Duration defaults to "1h".
func newWizard(defaultUser string) *wizard {
	w := &wizard{styles: makeWizardStyle()}
	if defaultUser != "" {
		w.user.cur = defaultUser
		w.user.pos = len([]rune(defaultUser))
	}
	w.host.cur = "*"
	w.host.pos = 1
	w.duration.options = durationPresets
	w.duration.index = 2 // "1h"
	return w
}

// Init satisfies bubbletea.Model.
func (w *wizard) Init() tea.Cmd { return nil }

// currentText returns the active text field for the current step.
func (w *wizard) currentText() *textInput {
	switch w.step {
	case stepUsername:
		return &w.user
	case stepHost:
		return &w.host
	default:
		return &w.reason
	}
}

// Update handles keystrokes and advances the wizard.
func (w *wizard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			w.val.canceled = true
			return w, tea.Quit
		case "enter", "tab":
			return w.handleAdvance()
		case "shift+tab":
			if w.step > stepUsername {
				w.step--
			}
			return w, nil
		case "up":
			if w.step == stepDuration && !w.durCustomVisible() {
				w.duration.up()
			}
			return w, nil
		case "down":
			if w.step == stepDuration && !w.durCustomVisible() {
				w.duration.down()
			}
			return w, nil
		case "left":
			if w.editingText() {
				w.currentText().left()
			}
			return w, nil
		case "right":
			if w.editingText() {
				w.currentText().right()
			}
			return w, nil
		case "backspace":
			if w.step == stepReason {
				w.reason.backspace()
			} else if w.step == stepDuration && w.durCustomVisible() {
				w.durCustom.backspace()
			} else if w.step == stepUsername {
				w.user.backspace()
			} else if w.step == stepHost {
				w.host.backspace()
			}
			return w, nil
		}

		// Printable runes inserted into the active text field.
		if len(msg.Runes) > 0 && msg.Type == tea.KeyRunes {
			switch w.step {
			case stepUsername:
				insertRunes(&w.user, msg.Runes)
			case stepHost:
				insertRunes(&w.host, msg.Runes)
			case stepReason:
				insertRunes(&w.reason, msg.Runes)
			case stepDuration:
				if w.duration.isCustom() {
					insertRunes(&w.durCustom, msg.Runes)
				}
			}
		}
	}
	return w, nil
}

// durCustomVisible reports whether the duration step is in free-text mode.
func (w *wizard) durCustomVisible() bool { return w.step == stepDuration && w.duration.isCustom() }

// editingText reports whether the current step edits a text field.
func (w *wizard) editingText() bool {
	return w.step != stepDuration || w.duration.isCustom()
}

// insertRunes inserts a batch of runes into a text field at its cursor.
func insertRunes(t *textInput, runes []rune) {
	for _, r := range runes {
		t.insert(r)
	}
}

// handleAdvance validates the current step and moves forward.
func (w *wizard) handleAdvance() (tea.Model, tea.Cmd) {
	switch w.step {
	case stepUsername:
		if w.user.cur == "" {
			return w, nil // require a username
		}
		w.val.Username = w.user.cur
	case stepHost:
		if w.host.cur == "" {
			w.host.cur = "*"
		}
		w.val.Target = w.host.cur
	case stepDuration:
		if w.duration.isCustom() {
			if w.durCustom.cur == "" {
				return w, nil // require a custom duration
			}
			w.val.Duration = w.durCustom.cur
		} else {
			w.val.Duration = w.duration.selected()
		}
	case stepReason:
		w.val.Reason = w.reason.cur
		w.done = true
		return w, tea.Quit
	}
	if w.step < stepCount-1 {
		w.step++
	}
	return w, nil
}

// View renders the current wizard state.
func (w *wizard) View() string {
	var b strings.Builder
	b.WriteString(w.styles.title.Render("warden request") + "\n\n")

	for i, title := range stepTitles {
		num := fmt.Sprintf("%d/%d", i+1, stepCount)
		if w.done || i < w.step {
			val := w.valForStep(i)
			b.WriteString(w.styles.check.Render("✓ ") +
				w.styles.field.Render(fmt.Sprintf("%s %-18s", num, title)) +
				" " + w.styles.accent.Render(val) + "\n")
			continue
		}
		if i == w.step {
			heading := w.styles.accent.Render(fmt.Sprintf("%s %s", num, title))
			hint := w.styles.field.Render("— " + stepHints[i])
			b.WriteString(heading + " " + hint + "\n")
			b.WriteString(w.renderStep(i) + "\n")
		} else {
			b.WriteString(w.styles.field.Render(fmt.Sprintf("%s %-18s", num, title)) + "\n")
		}
	}

	b.WriteString("\n" + w.helpText())
	return w.styles.box.Render(b.String())
}

// valForStep returns the value of a completed step for rendering.
func (w *wizard) valForStep(step int) string {
	switch step {
	case stepUsername:
		return w.val.Username
	case stepHost:
		return w.val.Target
	case stepDuration:
		return w.val.Duration
	default:
		return w.val.Reason
	}
}

// renderStep renders the interactive field for the given step.
func (w *wizard) renderStep(step int) string {
	switch step {
	case stepDuration:
		return w.renderDuration()
	default:
		return w.renderTextInput(w.currentText())
	}
}

// renderTextInput renders a single-line input with a cursor marker.
func (w *wizard) renderTextInput(in *textInput) string {
	runes := []rune(in.cur)
	if in.pos < 0 {
		in.pos = 0
	}
	if in.pos > len(runes) {
		in.pos = len(runes)
	}
	before := w.styles.field.Render(string(runes[:in.pos]))
	cursor := w.styles.cursorBg.Render(" ")
	if in.pos == len(runes) {
		return before + cursor
	}
	return before + w.styles.focused.Render(string(runes[in.pos])) + w.styles.field.Render(string(runes[in.pos+1:]))
}

// renderDuration renders either the preset list or the custom input.
func (w *wizard) renderDuration() string {
	if w.duration.isCustom() {
		return w.renderTextInput(&w.durCustom)
	}
	var b strings.Builder
	for i, opt := range w.duration.options {
		line := "  " + opt
		if i == w.duration.index {
			line = w.styles.selected.Render("▸ " + opt)
		} else {
			line = w.styles.option.Render("  " + opt)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// helpText renders the keyboard hints shown at the bottom of the view.
func (w *wizard) helpText() string {
	var hint string
	switch {
	case w.step == stepDuration && !w.duration.isCustom():
		hint = "↑/↓ choose · Enter next · ⇧Tab back · Esc quit"
	default:
		hint = "type to edit · Enter next · ⇧Tab back · Esc quit"
	}
	return w.styles.help.Render(hint)
}

// Result returns the values collected so far by the wizard.
func (w *wizard) Result() requestResult {
	return w.val
}

// runWizard runs the interactive Bubbletea program and returns the collected
// result. An error is returned if bubbletea fails to start.
func runWizard(defaultUser string) (requestResult, error) {
	w := newWizard(defaultUser)
	p := tea.NewProgram(w)
	final, err := p.Run()
	if err != nil {
		return requestResult{}, err
	}
	model, ok := final.(*wizard)
	if !ok {
		return requestResult{}, fmt.Errorf("unexpected bubbletea model %T", final)
	}
	model.val.Username = strings.TrimSpace(model.val.Username)
	model.val.Target = strings.TrimSpace(model.val.Target)
	model.val.Duration = strings.TrimSpace(model.val.Duration)
	model.val.Reason = strings.TrimSpace(model.val.Reason)
	return model.val, nil
}
