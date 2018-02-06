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

package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/padmeio/padme/enforcer"
	"github.com/padmeio/padme/policy"
)

// ConfigurePolicyRoutes configures the exposed HTTP endpoints for policy management
func ConfigurePolicyRoutes(router *mux.Router) {
	router.HandleFunc("/policies", GetPolicies).Methods("GET")
	router.HandleFunc("/policies", SavePolicies).Methods("POST")
}

// GetPolicies gets the PolicyBundle configured for the enforcer
func GetPolicies(w http.ResponseWriter, r *http.Request) {
	bundle, err := enforcer.Store.Get()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if bundle == nil {
		http.NotFound(w, r)
		return
	}

	json.NewEncoder(w).Encode(bundle)
}

// SavePolicies stores (creates or updates) a PolicyBundle for the enforcer.
func SavePolicies(w http.ResponseWriter, r *http.Request) {
	bundle := &policy.PolicyBundle{}
	if err := json.NewDecoder(r.Body).Decode(bundle); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	enforcer.Store.Save(bundle)
}
