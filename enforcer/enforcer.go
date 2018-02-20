/*
Copyright 2017 Kamil Pawlowski, Ignasi Barrera

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

// Package enforcer contains the PADME Enforcer definition. See relevant docs.
//
// This package defines the different enforcer APIs and provides interfaces to
// convert any request into a PADME Resource so it can be evaluated against the
// policies known to the enforcer.
package enforcer

import (
	"fmt"
	"log"
	"time"

	"github.com/padmeio/padme/enforcer/store"
	"github.com/padmeio/padme/policy"
)

// Enforcer is the main implementation of a PADME Enforcer.
type Enforcer struct {

	// Store configures the repository where the policies for this enforcer
	// are stored.
	Store store.PolicyRepository

	// Controllers are the list of controllers known to this enforcer that
	// are subscribed to policy events
	//
	// TODO nacx: How to implement persistence here in case an enforcer is
	// restarted? (for example after recovering from a crash)
	Controllers map[string]PolicyEventHandler
}

// NewEnforcer builds a new Enforcer object with the given policy repository
func NewEnforcer(store store.PolicyRepository) Enforcer {
	return Enforcer{
		Store:       store,
		Controllers: make(map[string]PolicyEventHandler),
	}
}

// Implementation of the Request Level Answer API

// Answer is the implementation of the Enforcer Answer API. It takes an access request for a
// given resource and evaluates it against the existing policies.
func (e *Enforcer) Answer(properties []*policy.Rule, credential *policy.Credential) bool {
	var bundle *policy.PolicyBundle
	if bundle = e.Fetch(); bundle == nil {
		return false
	}

	resource, err := assemble(properties, credential)
	if err != nil {
		log.Printf("Error assembling the request into a Policy Resource: %v", err)
		return false
	}

	// TODO nacx: Proper target, time and location?
	valid, accept, allow := bundle.Match(resource, nil, time.Now(), nil /*location*/)
	return valid && (!accept || allow)
}

// assemble takes a set of Rules and credentials and builds a Resource object to be
// evaluated against existing policies.
func assemble(properties []*policy.Rule, credential *policy.Credential) (*policy.Resource, error) {
	resource := &policy.Resource{IdentifiedBy: credential}
	if len(properties) == 0 {
		return nil, fmt.Errorf("at least one property must be defined")
	}
	ruleset := &policy.RuleSet{OOperator: policy.NONE, RRule: properties[0]}
	// TODO nacx: Test when there is just one element
	for _, rule := range properties[1:] {
		ruleset = ruleset.And(&policy.RuleSet{OOperator: policy.NONE, RRule: rule})
	}
	resource.Name = ruleset
	return resource, nil
}

// Implementation of the Controller API

// Fetch retrieves the current PolicyBundle
func (e *Enforcer) Fetch() *policy.PolicyBundle {
	bundle, err := e.Store.Get()
	if err != nil {
		log.Printf("Error loading policy bundle: %v", err)
		return nil
	}
	return bundle
}

// Apply applies the given PolicyBundle to this enforcer.
//
// If there is already a PolicyBundle, it will be updated with the
// added or removed policies
func (e *Enforcer) Apply(bundle *policy.PolicyBundle) bool {
	log.Printf("Applying policy bundle: %v...", bundle.Description)

	// TODO nacx: In order to partially update a PolicyBundle we need first to define
	// Policy equality. We need to be able to determine if two policies are equal, and to
	// test wether a Policy is present in a given bundle
	err := e.Store.Save(bundle)

	var event PolicyEvent
	var details string

	if err != nil {
		log.Printf("Error applying policy bundle: %v", err)
		event = PolicyApplyError
		details = err.Error()
	} else {
		event = PolicyApply
		details = "policy applied"
	}

	e.notify(event, details, bundle)

	return err == nil
}

// Register a given controller in this enforcer and subscribe it to policy events
func (e *Enforcer) Register(id string, handler PolicyEventHandler) bool {
	log.Printf("Registering controller %v...", id)
	if h, ok := e.Controllers[id]; !ok {
		log.Printf("Error registering handler %v. A handler with id %v already exists: %v", handler, id, h)
		return false
	}
	e.Controllers[id] = handler
	return true
}

// Unregister a controller from this enforcer and unsubscribe it from polocy events
func (e *Enforcer) Unregister(id string) {
	log.Printf("Unregistering controller %v...", id)
	delete(e.Controllers, id)
}

// notify all registered controllers a policy event for the given PolicyBundle
func (e *Enforcer) notify(event PolicyEvent, details string, bundle *policy.PolicyBundle) {
	for _, controller := range e.Controllers {
		controller.Handle(event, bundle.PolicyVersion, bundle.Description, details)
	}
}
