/*
Copyright 2018 Ignasi Barrera

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package enforcer

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	store "github.com/padmeio/padme/enforcer/store/filesystem"
	"github.com/padmeio/padme/policy"
)

var testFile = fmt.Sprintf("%v/src/github.com/padmeio/padme/policy/test_policy.json", os.Getenv("GOPATH"))
var bundle = loadTestPolicy(testFile)
var testStore = store.LocalPolicyRepository{FilePath: "/tmp/padme-enforcer.json"}

// List of all policies and all policies that define plugin data
var totalPolicies = len(bundle.Filter(func(p *policy.Policy) bool { return true }))
var pluginPolicies = len(bundle.Filter(func(p *policy.Policy) bool {
	return p.CContents != nil && len(p.CContents) > 0
}))

// lastEvent is a PolicyEventHandler that keeps track of the last fired event
type lastEvent struct {
	event PolicyEvent
}

func (h *lastEvent) Handle(event PolicyEvent, policyVersion uint64, policyDescription string, notes string) {
	h.event = event
}

// testPlugin is a Plugin that keeps track of the number of policies pushed to the plugin
type testPlugin struct {
	id              string
	appliedPolicies int
}

func (p *testPlugin) ID() string {
	return p.id
}

func (p *testPlugin) Apply(id string, data []byte) (bool, string) {
	p.appliedPolicies++
	return true, ""
}

func (p *testPlugin) Remove(id string) (bool, string) {
	p.appliedPolicies--
	return true, ""
}

func loadTestPolicy(path string) *policy.PolicyBundle {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Unable to read test policy file: %v", err))
	}
	bundle := &policy.PolicyBundle{}
	if err = json.Unmarshal(bytes, bundle); err != nil {
		panic(fmt.Sprintf("Unable to deserialize PolicyBundle: %v", err))
	}

	return bundle
}

// Controller API tests

func TestFetchOnFailure(t *testing.T) {
	st := store.LocalPolicyRepository{FilePath: "/dev/null"}
	invalid := NewEnforcer(&st)
	if bundle := invalid.Fetch(); bundle != nil {
		t.Fatal("Expected fetch to have failed on an invalid enforcer storage")
	}
}

func TestApplyAndFetch(t *testing.T) {
	e := NewEnforcer(&testStore)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	if retrieved := e.Fetch(); retrieved.Description != bundle.Description {
		t.Fatalf("Expected current policy to be %v but was: %v", bundle, retrieved)
	}
}

func TestRegisterHandler(t *testing.T) {
	e := NewEnforcer(&testStore)
	handler := lastEvent{}
	if registered := e.RegisterHandler("h", &handler); !registered {
		t.Fatal("Expected handler to be registered")
	}

	if _, ok := e.Handlers["h"]; !ok {
		t.Fatal("Expected handler to be present in the enforcer map")
	}

	// Duplicated IDs are not permitted
	if registered := e.RegisterHandler("h", &lastEvent{}); registered {
		t.Fatal("Duplicate IDs should not be allowed")
	}

	e.UnregisterHandler("h")
	if _, ok := e.Handlers["h"]; ok {
		t.Fatal("Expected handler to not be present in the enforcer map")
	}
}

func TestPlugins(t *testing.T) {
	e := NewEnforcer(&testStore)
	if l := len(e.Plugins()); l != 0 {
		t.Fatalf("Expected plugins to be empty, but found: %v", l)
	}

	plugin := testPlugin{id: "dummy", appliedPolicies: 5}
	e.RegisteredPlugins["dummy"] = &loadedPlugin{&plugin, true}

	plugins := e.Plugins()
	if l := len(plugins); l != 1 {
		t.Fatalf("Expected one plugin but found: %v", l)
	}
	if plugins[0] != plugin.ID() {
		t.Fatalf("Expected plugin to be: %v", plugin)
	}
}

func TestEnableNonRegisteredPlugin(t *testing.T) {
	e := NewEnforcer(&testStore)
	if enabled := e.Enable("unexisting"); enabled {
		t.Fatal("Plugin is not registered but has been enabled")
	}
}

func TestEnableAlreadyEnabledPlugin(t *testing.T) {
	e := NewEnforcer(&testStore)
	plugin := testPlugin{id: "test_plugin", appliedPolicies: 0}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, true}

	if enabled := e.Enable(plugin.ID()); enabled {
		t.Fatal("Plugin has been enabled despite being already enabled")
	}
}

func testEnablePlugin(t *testing.T) {
	e := NewEnforcer(&testStore)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "vendor_plugin", appliedPolicies: 0}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, false}

	if enabled := e.Enable(plugin.ID()); !enabled {
		t.Fatal("Expected the plugin to be enabled")
	}

	if plugin.appliedPolicies != pluginPolicies {
		t.Fatalf("Expected %v to be applied after enabling but found: %v", pluginPolicies, plugin.appliedPolicies)
	}
}

func testEnablePluginWithoutPolicies(t *testing.T) {
	e := NewEnforcer(&testStore)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "no_policies", appliedPolicies: 0}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, false}

	if enabled := e.Enable(plugin.ID()); !enabled {
		t.Fatal("Expected the plugin to be enabled")
	}

	if plugin.appliedPolicies != 0 {
		t.Fatalf("Expected no policies to be applied after enabling but found: %v", plugin.appliedPolicies)
	}
}

func TestDisableNonRegisteredPlugin(t *testing.T) {
	e := NewEnforcer(&testStore)
	if disabled := e.Disable("unexisting"); disabled {
		t.Fatal("Plugin is not registered but has been disabled")
	}
}

func TestDisableAlreadyDisabledPlugin(t *testing.T) {
	e := NewEnforcer(&testStore)
	plugin := testPlugin{id: "test_plugin", appliedPolicies: 0}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, false}

	if disabled := e.Disable(plugin.ID()); disabled {
		t.Fatal("Plugin has been disabled despite being already disabled")
	}
}

func testDisablePlugin(t *testing.T) {
	e := NewEnforcer(&testStore)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "vendor_plugin", appliedPolicies: pluginPolicies}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, true}

	if disabled := e.Disable(plugin.ID()); !disabled {
		t.Fatal("Expected the plugin to be disabled")
	}

	if plugin.appliedPolicies != 0 {
		t.Fatalf("Expected %v to be removed after disabling but only %v were removed",
			pluginPolicies, pluginPolicies-plugin.appliedPolicies)
	}
}

func testDisablePluginWithoutPolicies(t *testing.T) {
	e := NewEnforcer(&testStore)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "no_policies", appliedPolicies: 5}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, true}

	if disabled := e.Disable(plugin.ID()); !disabled {
		t.Fatal("Expected the plugin to be disabled")
	}

	if plugin.appliedPolicies != 5 {
		t.Fatalf("Expected no policies to be removed after disabling but %v were removed",
			5-plugin.appliedPolicies)
	}
}

// Plugin API tests

func TestRegisterPlugin(t *testing.T) {
	e := NewEnforcer(&testStore)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "vendor_plugin", appliedPolicies: 0}
	if registered := e.RegisterPlugin(&plugin); !registered {
		t.Fatal("Expected the plugin to be registered")
	}

	if plugin.appliedPolicies != pluginPolicies {
		t.Fatalf("Expected %v to be applied but found: %v", pluginPolicies, plugin.appliedPolicies)
	}
}

func TestRegisterPluginWithoutPolicies(t *testing.T) {
	e := NewEnforcer(&testStore)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	noPolicies := testPlugin{id: "no_policies", appliedPolicies: 0}
	if registered := e.RegisterPlugin(&noPolicies); !registered {
		t.Fatal("Expected the plugin to be registered")
	}

	if noPolicies.appliedPolicies > 0 {
		t.Fatalf("Expected no policies to be applied but found: %v", noPolicies.appliedPolicies)
	}
}

func TestUnregisterPlugin(t *testing.T) {
	e := NewEnforcer(&testStore)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "vendor_plugin", appliedPolicies: pluginPolicies}
	e.RegisteredPlugins["vendor_plugin"] = &loadedPlugin{&plugin, true}
	if unregistered := e.UnregisterPlugin(&plugin); !unregistered {
		t.Fatal("Expected the plugin to be unregistered")
	}

	if plugin.appliedPolicies > 0 {
		t.Fatalf("Expected plugin to have no policies but found: %v", plugin.appliedPolicies)
	}
}

func TestUnregisterPluginWithoutPolicies(t *testing.T) {
	e := NewEnforcer(&testStore)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	noPolicies := testPlugin{id: "no_policies", appliedPolicies: 5}
	e.RegisteredPlugins["no_policies"] = &loadedPlugin{&noPolicies, true}
	if unregistered := e.UnregisterPlugin(&noPolicies); !unregistered {
		t.Fatal("Expected the plugin to be unregistered")
	}

	if noPolicies.appliedPolicies != 5 {
		t.Fatalf("Expected plugin policies to be unchanged but %v were removed", 5-noPolicies.appliedPolicies)
	}
}

func TestUnregisterUnexistingPlugin(t *testing.T) {
	e := NewEnforcer(&testStore)
	if unregistered := e.UnregisterPlugin(&testPlugin{id: "unexisting"}); unregistered {
		t.Fatal("Expected the plugin to not be unregistered")
	}
}
