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

// AnswerAPI defines the Request Level Answer API. It supports most normal services requests.
// For example a web services request for a specific target URL uses this call.
type AnswerAPI interface {

	// Answer matches a request described by properties and credential
	// against the rules known by this enforcer.
	//
	// properties are the intrinsic properties of a given request. For
	// example the source tcp port or the destination ip address, or the
	// target URI. These are composed (along with the credential)
	// into a resource object. Composition of the properties is done
	// using an AND operation.
	//
	// Care must be taken in this API to ensure that standard
	// values for Layer and LType are readily available.
	//
	// No wild carding is permitted in a request.
	//
	// true is returned if policies allow this request.
	// false is returned if policies do not allow this request.
	Answer(properties []*policy.Rule, credential *policy.Credential) bool
}

// Plugin defines the Plugin interface is implemented by or on behalf of an external
// Policy enforcement component. There can only be one
// plugin with a given id on any given enforcer, and this id must
// be consistent throughout the zone.
//
// Policies that have a non-empty CContents apply use this interface
// to configure the specified plugin.
//
// As there is no guarantee that the sub-component understands time.
// A policy is not applied to the plugin until the start time in
// its Duration field. It is unapplied at the end time.  This
// must be taken into account when testing policies.
//
// Registered, Unregistered, Enabled, Disabled.
//
// Plugins register themselves with the enforcer when they
// are ready to operate and unregister themselves when
// they are no longer able or willing to operate. Additionally
// controllers can instruct enforcers to ignore certain
// plugins by disabling them.
//
// By default specific plugins are disabled.
type Plugin interface {

	// Id returns the unique id of this plugin in the zone
	Id() string

	// Apply appies the policy information provided by a policy
	//
	// Parameters:
	//	id - an identified asserted by the enforcer through which subsequent operations regarding this policy.
	//	data - the Blob specified in the Contents part of the Policy
	//
	// return (bool, error)
	//	true - the policy was applied
	//	false - the policy was not applied
	//	string - a human readable error returned by the plugin. valid if false is returned.
	Apply(id int, data []byte) (bool, string)

	// Remove removes a policy that was previously applied
	//
	// Parameters:
	//	id - the id asserted when the policy was applied
	//
	// return (bool, error)
	//	true - the policy was removed, or did not exist
	//	false - the policy was not removed
	//	string - a human readable error returned by the plugin. valid if false is returned.
	Remove(id int) (bool, string)
}

// Enforcer is the main implementation of a PADME Enforcer.
type Enforcer struct {

	// Store configures the repository where the policies for this enforcer
	// are stored.
	Store store.PolicyStore
}

// assemble takes a set of Rules and credentials and builds a Resource object to be
// evaluated against existing policies.
func (e *Enforcer) assemble(properties []*policy.Rule, credential *policy.Credential) (*policy.Resource, error) {
	resource := &policy.Resource{IdentifiedBy: credential}
	if len(properties) == 0 {
		return nil, fmt.Errorf("At least one property must be defined")
	}
	ruleset := &policy.RuleSet{OOperator: policy.NONE, RRule: properties[0]}
	// TODO nacx: Test when there is just one element
	for _, rule := range properties[1:] {
		ruleset = ruleset.And(&policy.RuleSet{OOperator: policy.NONE, RRule: rule})
	}
	resource.Name = ruleset
	return resource, nil
}

// Answer is the implementation of the Enforcer Answer API. It takes an access request for a
// given resource and evaluates it against the existing policies.
func (e *Enforcer) Answer(properties []*policy.Rule, credential *policy.Credential) bool {
	bundle, err := e.Store.Get()
	if err != nil {
		log.Printf("error loading the polocy bundle: %v", err)
		return false
	}

	var resource *policy.Resource
	resource, err = e.assemble(properties, credential)
	if err != nil {
		log.Printf("error assembling the request into a Policy Resource: %v", err)
		return false
	}

	// TODO nacx: Proper target, time and location?
	valid, accept, allow := bundle.Match(resource, nil, time.Now(), nil /*location*/)
	return valid && (!accept || allow)
}
