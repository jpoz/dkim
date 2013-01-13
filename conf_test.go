package dkim

import (
	"crypto"
	"testing"
)

func TestNewConf(t *testing.T) {
	conf, err := NewConf("", "selector")
	if err == nil {
		t.Fatal("error nil")
	}
	conf, err = NewConf("domain", "")
	if err == nil {
		t.Fatal("error nil")
	}
	conf, err = NewConf("domain", "selector")
	if err != nil {
		t.Fatal("error not nil", err)
	}
	if len(conf) != 10 {
		t.Fatal("wrong number of keys")
	}
}

func TestIsValid(t *testing.T) {
	conf := Conf{}
	if conf.IsValid() {
		t.Fatal("conf should be invalid")
	}
	conf, err := NewConf("domain", "selector")
	if err != nil {
		t.Fatal("error not nil", err)
	}
	if !conf.IsValid() {
		t.Fatal("conf not valid")
	}
}

func TestAlgorithm(t *testing.T) {
	conf := Conf{}
	if conf.Algorithm() != AlgorithmSHA256 {
		t.Fatal("wrong algorithm")
	}
}

func TestHash(t *testing.T) {
	conf := Conf{}
	if conf.Hash() != crypto.SHA256 {
		t.Fatal("invalid hash", conf.Hash())
	}
}

func TestHeaderCanonicalization(t *testing.T) {
	conf := Conf{}
	if conf.HeaderCanonicalization() != SimpleCanonicalization {
		t.Fatal("not simple")
	}
	conf = Conf{CanonicalizationKey: "relaxed/simple"}
	if conf.HeaderCanonicalization() != RelaxedCanonicalization {
		t.Fatal("not relaxed")
	}
	conf = Conf{CanonicalizationKey: "simple/relaxed"}
	if conf.HeaderCanonicalization() != SimpleCanonicalization {
		t.Fatal("not simple")
	}
	conf = Conf{CanonicalizationKey: "relaxed"}
	if conf.HeaderCanonicalization() != RelaxedCanonicalization {
		t.Fatal("not relaxed")
	}
	conf = Conf{CanonicalizationKey: "simple/simple"}
	if conf.HeaderCanonicalization() != SimpleCanonicalization {
		t.Fatal("not simple")
	}
	conf = Conf{CanonicalizationKey: "simple"}
	if conf.HeaderCanonicalization() != SimpleCanonicalization {
		t.Fatal("not simple")
	}
	conf = Conf{CanonicalizationKey: "relaxed/relaxed"}
	if conf.HeaderCanonicalization() != RelaxedCanonicalization {
		t.Fatal("not relaxed")
	}
}

func TestBodyCanonicalization(t *testing.T) {
	conf := Conf{}
	if conf.BodyCanonicalization() != SimpleCanonicalization {
		t.Fatal("not simple")
	}
	conf = Conf{CanonicalizationKey: "relaxed/simple"}
	if conf.BodyCanonicalization() != SimpleCanonicalization {
		t.Fatal("not simple")
	}
	conf = Conf{CanonicalizationKey: "simple/relaxed"}
	if conf.BodyCanonicalization() != RelaxedCanonicalization {
		t.Fatal("not relaxed")
	}
	conf = Conf{CanonicalizationKey: "relaxed"}
	if conf.BodyCanonicalization() != SimpleCanonicalization {
		t.Fatal("not simple")
	}
	conf = Conf{CanonicalizationKey: "simple/simple"}
	if conf.BodyCanonicalization() != SimpleCanonicalization {
		t.Fatal("not simple")
	}
	conf = Conf{CanonicalizationKey: "simple"}
	if conf.BodyCanonicalization() != SimpleCanonicalization {
		t.Fatal("not simple")
	}
	conf = Conf{CanonicalizationKey: "relaxed/relaxed"}
	if conf.BodyCanonicalization() != RelaxedCanonicalization {
		t.Fatal("not relaxed")
	}
}

func TestJoin(t *testing.T) {
	conf := Conf{}
	if conf.Join() != "" {
		t.Fatal("uninitialized join should yield empty string")
	}
	conf, err := NewConf("domain", "selector")
	if err != nil {
		t.Fatal("error not nil", err)
	}
	ts := conf[TimestampKey]
	join := conf.Join()
	if join != "v=1; a=rsa-sha256; c=relaxed/simple; d=domain; q=dns/txt; s=selector; t="+ts+"; bh=; h=; b=" {
		t.Fatal("invalid join", join)
	}
}
