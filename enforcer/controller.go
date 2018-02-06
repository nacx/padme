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

package enforcer

import (
	"github.com/padmeio/padme/policy"
)

// Controller API defines interactions between an Enforcer and a Controller.
// Controller/Enforcer discovery is presently not covered here. Mutual knowledge
// is assumed. This API is also agnostic as to whether or not push or pull is
// used between the Enforcer and Controller.
type Controller interface {

	// Apply a policy bundle to the enforcer.
	//
	// Policies are specifically ordered.  Thus the addition, removal, or
	// modification of one or more policy requires a new policy bundle to
	// be applied to the enforcer. The enforcer is responsbile for
	// determining which policies have been added or removed and
	// modifiying its state or the state of its plugins as necessary.
	// If no PolicyVersions change, and no policies are added
	// or removed, then nothing is done.
	//
	// A return code is provided, however failures for individual policies
	// are returned via the PolicyEventHandler.
	//
	// Rollback is achieved by shipping an old policy bundle with higher
	// version numbers.
	//
	// Parameters:
	//  bundle - the policy bundle to apply
	//
	// Return:
	//   true - all policies were applied
	//   false - some polices were not applied, see PolicyEventHandler
	//     for specific issues
	Apply(bundle *policy.PolicyBundle) bool

	// Fetch the current policy bundle from this enfocer
	Fetch() *policy.PolicyBundle
}
