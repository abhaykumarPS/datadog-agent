// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build functionaltests

package tests

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	sprobe "github.com/DataDog/datadog-agent/pkg/security/probe"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
)

func TestInitModule(t *testing.T) {
	if testEnvironment == DockerEnvironment {
		t.Skip("skipping kernel module test in docker")
	}

	_, err := os.Stat("/tmp/test_module.ko")
	if err != nil {
		// we assume that the test module couldn't be built, skip the test
		t.Skip("/tmp/test_module.ko couldn't be opened, skipping")
	}

	// make sure the test module isn't currently loaded
	_ = unix.DeleteModule("test_module", unix.O_NONBLOCK)

	ruleDefs := []*rules.RuleDefinition{
		{
			ID:         "test_init_module_from_memory",
			Expression: `init_module.name == "test_module" && init_module.loaded_from_memory == true`,
		},
		{
			ID:         "test_init_module",
			Expression: `init_module.name == "test_module" && init_module.file.path == "/tmp/test_module.ko" && init_module.loaded_from_memory == false`,
		},
	}

	test, err := newTestModule(t, nil, ruleDefs, testOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	t.Run("init_module", func(t *testing.T) {
		test.WaitSignal(t, func() error {
			var f *os.File
			f, err = os.Open("/tmp/test_module.ko")
			if err != nil {
				return fmt.Errorf("couldn't open test_module: %w", err)
			}
			defer f.Close()

			var module []byte
			module, err = io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("couldn't load test_module content: %w", err)
			}

			if err = unix.InitModule(module, ""); err != nil {
				return fmt.Errorf("couldn't insert module: %w", err)
			}

			return unix.DeleteModule("test_module", unix.O_NONBLOCK)
		}, func(event *sprobe.Event, r *rules.Rule) {
			assert.Equal(t, "test_init_module_from_memory", r.ID, "invalid rule triggered")
			assert.Equal(t, "", event.ResolveFilePath(&event.InitModule.File), "shouldn't get a path")

			if !validateModuleSchema(t, event) {
				t.Error(event.String())
			}
		})
	})

	t.Run("finit_module", func(t *testing.T) {
		test.WaitSignal(t, func() error {
			var f *os.File
			f, err = os.Open("/tmp/test_module.ko")
			if err != nil {
				return fmt.Errorf("couldn't open test_module: %w", err)
			}
			defer f.Close()

			if err = unix.FinitModule(int(f.Fd()), "", 0); err != nil {
				return fmt.Errorf("couldn't insert module: %w", err)
			}

			return unix.DeleteModule("test_module", unix.O_NONBLOCK)
		}, func(event *sprobe.Event, r *rules.Rule) {
			assert.Equal(t, "test_init_module", r.ID, "invalid rule triggered")

			if !validateModuleSchema(t, event) {
				t.Error(event.String())
			}
		})
	})
}

func TestDeleteModule(t *testing.T) {
	if testEnvironment == DockerEnvironment {
		t.Skip("skipping kernel module test in docker")
	}

	_, err := os.Stat("/tmp/test_module.ko")
	if err != nil {
		// we assume that the test module couldn't be built, skip the test
		t.Skip("/tmp/test_module.ko couldn't be opened, skipping")
	}

	// make sure the test module isn't currently loaded
	_ = unix.DeleteModule("test_module", unix.O_NONBLOCK)

	ruleDefs := []*rules.RuleDefinition{
		{
			ID:         "test_delete_module",
			Expression: `delete_module.name == "test_module"`,
		},
	}

	test, err := newTestModule(t, nil, ruleDefs, testOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	t.Run("delete_module", func(t *testing.T) {
		test.WaitSignal(t, func() error {
			var f *os.File
			f, err = os.Open("/tmp/test_module.ko")
			if err != nil {
				return fmt.Errorf("couldn't open test_module: %w", err)
			}
			defer f.Close()

			var module []byte
			module, err = io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("couldn't load test_module content: %w", err)
			}

			if err = unix.InitModule(module, ""); err != nil {
				return fmt.Errorf("couldn't insert module: %w", err)
			}

			return unix.DeleteModule("test_module", unix.O_NONBLOCK)
		}, func(event *sprobe.Event, r *rules.Rule) {
			assert.Equal(t, "test_delete_module", r.ID, "invalid rule triggered")

			if !validateModuleSchema(t, event) {
				t.Error(event.String())
			}
		})
	})
}
