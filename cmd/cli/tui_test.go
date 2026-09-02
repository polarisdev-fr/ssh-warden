package main

import (
	"testing"

	"github.com/charmbracelet/bubbletea"
)

// typeKeys is a helper that feeds a sequence of keys to the wizard's Update.
func typeKeys(t *testing.T, w *wizard, keys ...tea.KeyMsg) *wizard {
	t.Helper()
	var m tea.Model = w
	for _, k := range keys {
		next, _ := m.Update(k)
		m = next
	}
	res, ok := m.(*wizard)
	if !ok {
		t.Fatalf("unexpected model type %T", m)
	}
	return res
}

func keyRunes(r rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
}

func TestWizardFullFlow(t *testing.T) {
	w := newWizard("alice")

	// Step 1: pre-filled with alice; accept the default.
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyEnter})

	// Step 2: host pre-filled "*"; clear it and enter a custom target.
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyBackspace})
	w = typeKeys(t, w, keyRunes('s'), keyRunes('r'), keyRunes('v'), keyRunes('-'), keyRunes('x'))
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyEnter})

	// Step 3: duration — default is "1h" (index 2); move down once to "2h".
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyDown})
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyEnter})

	// Step 4: type a reason and finish.
	w = typeKeys(t, w, keyRunes('t'), keyRunes('e'), keyRunes('s'), keyRunes('t'))
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyEnter})

	res := w.Result()
	if res.Canceled() {
		t.Fatal("expected a completed result, got canceled")
	}
	if res.Username != "alice" {
		t.Errorf("username = %q, want alice", res.Username)
	}
	if res.Target != "srv-x" {
		t.Errorf("target = %q, want srv-x", res.Target)
	}
	if res.Duration != "2h" {
		t.Errorf("duration = %q, want 2h", res.Duration)
	}
	if res.Reason != "test" {
		t.Errorf("reason = %q, want test", res.Reason)
	}
}

func TestWizardCancel(t *testing.T) {
	w := newWizard("")
	// Hit Esc at the first step.
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyEsc})
	if !w.Result().Canceled() {
		t.Error("expected wizard to be canceled after Esc")
	}
}

func TestWizardEmptyUsernameBlocked(t *testing.T) {
	w := newWizard("")
	// Press Enter without typing a username: must not advance.
	before := w.step
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyEnter})
	if w.step != before {
		t.Errorf("step advanced to %d without a username", w.step)
	}
}

func TestWizardCustomDuration(t *testing.T) {
	w := newWizard("alice")
	// Enter on username, Enter on host (default "*").
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyEnter})
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyEnter})

	// Move down to "Custom..." (index 2 -> 6) then Enter to open free text.
	for i := 0; i < 4; i++ {
		w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyDown})
	}
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyEnter})

	// The duration step now accepts a custom value: select "3h45m".
	w = typeKeys(t, w, keyRunes('3'), keyRunes('h'), keyRunes('4'), keyRunes('5'), keyRunes('m'))
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyEnter})

	// Finish.
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyEnter})

	res := w.Result()
	if res.Duration != "3h45m" {
		t.Errorf("custom duration = %q, want 3h45m", res.Duration)
	}
}

func TestWizardBackNavigation(t *testing.T) {
	w := newWizard("alice")
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyEnter})    // username -> host
	w = typeKeys(t, w, tea.KeyMsg{Type: tea.KeyShiftTab}) // back to username
	if w.step != stepUsername {
		t.Errorf("expected to return to username step, got %d", w.step)
	}
}
