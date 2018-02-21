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

func (p *testPlugin) Id() string {
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
		t.Error("Expected fetch to have failed on an invalid enforcer storage")
	}
}

func TestApplyAndFetch(t *testing.T) {
	e := NewEnforcer(&testStore)
	if ok := e.Apply(bundle); !ok {
		t.Error("Expected policy to be applied to the enforcer")
	}

	if retrieved := e.Fetch(); retrieved.Description != bundle.Description {
		t.Errorf("Expected current policy to be %v but was: %v", bundle, retrieved)
	}
}

func TestRegisterHandler(t *testing.T) {
	e := NewEnforcer(&testStore)
	handler := lastEvent{}
	if registered := e.RegisterHandler("h", &handler); !registered {
		t.Error("Expected handler to be registered")
	}

	if _, ok := e.Handlers["h"]; !ok {
		t.Error("Expected handler to be present in the enforcer map")
	}

	// Duplicated IDs are not permitted
	if registered := e.RegisterHandler("h", &lastEvent{}); registered {
		t.Error("Duplicate IDs should not be allowed")
	}

	e.UnregisterHandler("h")
	if _, ok := e.Handlers["h"]; ok {
		t.Error("Expected handler to not be present in the enforcer map")
	}
}

// Plugin API tests

func TestRegisterPlugin(t *testing.T) {
	e := NewEnforcer(&testStore)
	totalPolicies := len(bundle.Filter(func(p *policy.Policy) bool { return true }))
	pluginPolicies := len(bundle.Filter(func(p *policy.Policy) bool {
		return p.CContents != nil && len(p.CContents) > 0
	}))

	if pluginPolicies >= totalPolicies {
		t.Errorf("Expected to have less plugin policies (%v) than total policies (%v)",
			pluginPolicies, totalPolicies)
	}

	if ok := e.Apply(bundle); !ok {
		t.Error("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "vendor_plugin", appliedPolicies: 0}
	if registered := e.RegisterPlugin(&plugin); !registered {
		t.Error("Expected the plugin to be registered")
	}

	if plugin.appliedPolicies != pluginPolicies {
		t.Errorf("Expected %v to be applied but found: %v", pluginPolicies, plugin.appliedPolicies)
	}

	// Register a plugin with no policies associated
	noPolicies := testPlugin{id: "no_policies", appliedPolicies: 0}
	if registered := e.RegisterPlugin(&noPolicies); !registered {
		t.Error("Expected the plugin to be registered")
	}

	if noPolicies.appliedPolicies > 0 {
		t.Errorf("Expected no policies to be applied but found: %v", noPolicies.appliedPolicies)
	}
}

func TestUnregisterPlugin(t *testing.T) {
	e := NewEnforcer(&testStore)
	totalPolicies := len(bundle.Filter(func(p *policy.Policy) bool { return true }))
	pluginPolicies := len(bundle.Filter(func(p *policy.Policy) bool {
		return p.CContents != nil && len(p.CContents) > 0
	}))

	if pluginPolicies >= totalPolicies {
		t.Errorf("Expected to have less plugin policies (%v) than total policies (%v)",
			pluginPolicies, totalPolicies)
	}

	if ok := e.Apply(bundle); !ok {
		t.Error("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "vendor_plugin", appliedPolicies: pluginPolicies}
	e.Plugins["vendor_plugin"] = &plugin
	if unregistered := e.UnregisterPlugin(&plugin); !unregistered {
		t.Error("Expected the plugin to be unregistered")
	}

	if plugin.appliedPolicies > 0 {
		t.Errorf("Expected plugin to have no policies but found: %v", plugin.appliedPolicies)
	}

	// Unregister a plugin with no policies associated
	noPolicies := testPlugin{id: "no_policies", appliedPolicies: 5}
	e.Plugins["no_policies"] = &noPolicies
	if unregistered := e.UnregisterPlugin(&noPolicies); !unregistered {
		t.Error("Expected the plugin to be unregistered")
	}

	if noPolicies.appliedPolicies != 5 {
		t.Errorf("Expected plugin policies to be unchanged but %v were removed", 5-noPolicies.appliedPolicies)
	}

	if unregistered := e.UnregisterPlugin(&testPlugin{id: "unexisting"}); unregistered {
		t.Error("Expected the plugin to not be unregistered")
	}
}
