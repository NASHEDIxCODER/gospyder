package registry

import (
	"context"
	"testing"
	"time"
)

type testModule struct{}

func (m testModule) Name() string {
	return "test"
}

func (m testModule) Description() string {
	return "test module"
}

func (m testModule) Run(ctx context.Context, opts Options) (*Result, error) {
	return &Result{
		Module:    m.Name(),
		Timestamp: time.Now(),
		Status:    "success",
		Target:    "example.com",
		Findings: []Finding{{
			Type:  "test",
			Value: "found",
		}},
	}, nil
}

func TestRegistryRegisterGetListAndRun(t *testing.T) {
	reg := New()
	mod := testModule{}

	if err := reg.Register(mod.Name(), mod); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if err := reg.Register(mod.Name(), mod); err == nil {
		t.Fatal("Register() duplicate error = nil")
	}

	got, err := reg.Get(mod.Name())
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Name() != mod.Name() {
		t.Fatalf("Get() name = %q, want %q", got.Name(), mod.Name())
	}

	result, err := reg.Run(context.Background(), mod.Name(), Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result == nil || len(result.Findings) != 1 {
		t.Fatalf("Run() result findings = %#v, want one finding", result)
	}

	list := reg.List()
	if len(list) != 1 || list[0].Name != mod.Name() {
		t.Fatalf("List() = %#v, want test module", list)
	}
}

func TestRegistryUnknownModule(t *testing.T) {
	reg := New()
	if _, err := reg.Get("missing"); err == nil {
		t.Fatal("Get() missing error = nil")
	}
	if _, err := reg.Run(context.Background(), "missing", Options{}); err == nil {
		t.Fatal("Run() missing error = nil")
	}
}
