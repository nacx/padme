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
var testStore = store.LocalPolicyRepository{FilePath: "/tmp/padme-enforcer.json"}
var e = NewEnforcer(&testStore)

type lastEvent struct {
	event PolicyEvent
}

func (h *lastEvent) Handle(event PolicyEvent, policyVersion uint64, policyDescription string, notes string) {
	h.event = event
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
	bundle := loadTestPolicy(testFile)
	if ok := e.Apply(bundle); !ok {
		t.Error("Expected policy to be applied to the enforcer")
	}

	if retrieved := e.Fetch(); retrieved.Description != bundle.Description {
		t.Errorf("Expected current policy to be %v but was: %v", bundle, retrieved)
	}
}

func TestRegisterHandler(t *testing.T) {
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
