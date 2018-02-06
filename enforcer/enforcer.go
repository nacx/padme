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

	"github.com/padmeio/padme/enforcer/store"
	"github.com/padmeio/padme/policy"
)

// Enforcer defines the main Enforcer API. Methods in this interface provide
// mechanisms to evaluate a set of Rules against the existing policies.
type Enforcer interface {

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
	// No wilding carding is permitted in a request.
	//
	// true is returned if policies allow this request.
	// false is returned if policies do not allow this request.
	//
	Answer(properties []*policy.Rule, credential *policy.Credential) bool
}

// Store is the PolicyStore instance that holds the policies this enforcer evaluates
var Store store.PolicyStore

// assemble takes a set of Rules and credentials and builds a Resource object to be
// evaluated against existing policies.
func assemble(properties []*policy.Rule, credential *policy.Credential) (*policy.Resource, error) {
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
