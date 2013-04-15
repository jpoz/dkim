package dkim

import (
	"testing"
)

var headerListSample []byte = []byte("A: X\r\n" +
	"B : Y\t\r\n" +
	"\tZ  \r\n" +
	"\r\n" +
	" C \r\n" +
	"D \t E\r\n" +
	"\r\n" +
	"\r\n")

func TestParseHeaderList(t *testing.T) {
	header, _, err := ReadEML(headerListSample)
	if err != nil {
		t.Fatal("error not nil", err)
	}
	list, err := ParseHeaderList(header)
	if err != nil {
		t.Fatal("error not nil", err)
	}
	if len(list) != 2 {
		t.Fatal("failed to parse header list")
	}
	a := list[0]
	v := a.RawKey + ":" + a.RawValue
	if v != "A: X" {
		t.Fatal("wrong value", v)
	}
	b := list[1]
	v = b.RawKey + ":" + b.RawValue
	if v != "B : Y\t\r\n\tZ  " {
		t.Fatal("wrong value", v)
	}
}

func TestGet(t *testing.T) {
	list := HeaderList{
		&Header{" A\t", "X y"},
		&Header{" b\t", " z"},
	}
	a, ok := list.Get("A")
	if !ok {
		t.Fatal("could not get header")
	}
	if a.RawValue != "X y" {
		t.Fatal("wrong value", a.RawValue)
	}
	b, ok := list.Get("B")
	if !ok {
		t.Fatal("could not get header")
	}
	if b.RawValue != " z" {
		t.Fatal("wrong value", b.RawValue)
	}
	c, ok := list.Get("C")
	if ok {
		t.Fatal("should not exist")
	}
	if c != nil {
		t.Fatal("should not return value")
	}
}

func TestFields(t *testing.T) {
	list := HeaderList{
		&Header{" A\t", "X y"},
		&Header{" b\t", " z"},
	}
	fields := list.Fields()
	if fields != "A:b" {
		t.Fatal("wrong fields", fields)
	}
}

func TestCanonical2(t *testing.T) {
	header, _, err := ReadEML(headerListSample)
	if err != nil {
		t.Fatal("error not nil", err)
	}
	list, err := ParseHeaderList(header)
	if err != nil {
		t.Fatal("error not nil", err)
	}
	if len(list) != 2 {
		t.Fatal("wrong header list count", len(list))
	}
	simple := list.Canonical(false)
	if simple != "A: X\r\nB : Y\t\r\n\tZ  \r\n" {
		t.Fatal("wrong simple canonical value", simple)
	}
	relaxed := list.Canonical(true)
	if relaxed != "a:X\r\nb:Y Z\r\n" {
		t.Fatal("wrong relaxed canonical value", relaxed)
	}
}
