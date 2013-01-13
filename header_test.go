package dkim

import (
	"testing"
)

func TestParseHeader(t *testing.T) {
	h, err := ParseHeader("\tX: A b ")
	if err != nil {
		t.Fatal("error not nil", err)
	}
	if h.RawKey != "\tX" {
		t.Fatal("raw key invalid", h.RawKey)
	}
	if h.RawValue != " A b " {
		t.Fatal("raw value invalid", h.RawValue)
	}
}

func TestKey(t *testing.T) {
	h := Header{" C\t", "A b"}
	if h.Key() != "C" {
		t.Fatal("wrong key", h.Key())
	}
}

func TestValue(t *testing.T) {
	h := Header{" C\t", "\t A B "}
	if h.Value() != "A B" {
		t.Fatal("wrong value", h.Value())
	}
}

func TestRelaxedKey(t *testing.T) {
	h := Header{" C\t", "A b"}
	if h.RelaxedKey() != "c" {
		t.Fatal("wrong relaxed key", h.RelaxedKey())
	}
}

func TestRelaxedValue(t *testing.T) {
	h := Header{" C\t", " \tA \t   b "}
	if h.RelaxedValue() != "A b" {
		t.Fatal("wrong relaxed value", h.RelaxedValue())
	}
}

func TestCanonical(t *testing.T) {
	h := Header{" C\t", " \tA \t   b "}
	can := h.Canonical(RelaxedCanonicalization)
	if can != "c:A b" {
		t.Fatal("wrong relaxed canonical value", can)
	}
	k := " C\t"
	v := " \tA \t   b "
	h = Header{k, v}
	can = h.Canonical(SimpleCanonicalization)
	if can != k+":"+v {
		t.Fatal("wrong simple canonical value", can)
	}
}
