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

// loaddedPlugin holds the information of a plugin that has been loaded by this enforcer,
// such as the enabled flag, plugin-specific configuration that needs to be known by the
// enforcer, etc.
type loadedPlugin struct {
	Plugin
	enabled bool
}

// Enforcer is the main implementation of a PADME Enforcer.
type Enforcer struct {

	// Store configures the repository where the policies for this enforcer
	// are stored.
	Store store.PolicyRepository

	// TODO nacx: How to implement persistence for plugins and controllers
	// in case an enforcer is restarted? (for example after recovering from a crash)

	// Handlers are the list of controllers known to this enforcer that
	// are subscribed to policy events
	Handlers map[string]PolicyEventHandler

	// RegisteredPlugins are the list of plugins this enforcer will delegate to when
	// checking policies for an incoming resource
	RegisteredPlugins map[string]*loadedPlugin
}

// NewEnforcer builds a new Enforcer object with the given policy repository
func NewEnforcer(store store.PolicyRepository) Enforcer {
	return Enforcer{
		Store:             store,
		Handlers:          make(map[string]PolicyEventHandler),
		RegisteredPlugins: make(map[string]*loadedPlugin),
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

	// TODO nacx: Proper target from this enforcer data, and location from config
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
func (e *Enforcer) Apply(bundle *policy.PolicyBundle) bool {
	log.Printf("Applying policy bundle: %v...", bundle.Description)

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

// RegisterHandler registers a given controller in this enforcer and subscribe it to policy events
func (e *Enforcer) RegisterHandler(id string, handler PolicyEventHandler) bool {
	log.Printf("Registering handler %v...", id)
	if h, present := e.Handlers[id]; present {
		log.Printf("Error registering handler %v. A handler with id %v already exists: %v", handler, id, h)
		return false
	}
	e.Handlers[id] = handler
	return true
}

// UnregisterHandler removes a controller from this enforcer and unsubscribe it from polocy events
func (e *Enforcer) UnregisterHandler(id string) {
	log.Printf("Unregistering handler %v...", id)
	delete(e.Handlers, id)
}

// notify all registered controllers a policy event for the given PolicyBundle
func (e *Enforcer) notify(event PolicyEvent, details string, bundle *policy.PolicyBundle) {
	for _, controller := range e.Handlers {
		controller.Handle(event, bundle.PolicyVersion, bundle.Description, details)
	}
}

// Plugins returns the IDs of all plugins registered in this enforcer.
func (e *Enforcer) Plugins() []string {
	plugins := make([]string, len(e.RegisteredPlugins))
	i := 0
	for p := range e.RegisteredPlugins {
		plugins[i] = p
		i++
	}
	return plugins
}

// Enable enables the given plugin, if not already enabled, and applies to it all policies that
// are configured for that plugin
func (e *Enforcer) Enable(pluginID string) bool {
	plugin, present := e.RegisteredPlugins[pluginID]
	if !present {
		log.Printf("Error enabling plugin: %v. Plugin not registered", pluginID)
		return false
	}

	if plugin.enabled {
		log.Printf("Plugin %v is already enabled. Ignoring", pluginID)
		return false
	}

	var bundle *policy.PolicyBundle
	if bundle = e.Fetch(); bundle == nil {
		log.Print("Error loading enforcer policies")
		return false
	}

	log.Printf("Enabling plugin %v...", pluginID)

	for _, p := range bundle.Filter(pluginFilter(plugin)) {
		log.Printf("Applying policy: %v...", p.Description)
		for _, content := range p.CContents {
			if content.PluginID == plugin.ID() {
				plugin.Apply(p.UUID, content.Blob)
			}
		}

	}

	plugin.enabled = true
	return true
}

// Disable disables the given plugin, if not already enabled, and applies to it all policies that
// are configured for that plugin
func (e *Enforcer) Disable(pluginID string) bool {
	plugin, present := e.RegisteredPlugins[pluginID]
	if !present {
		log.Printf("Error disabling plugin: %v. Plugin not registered", pluginID)
		return false
	}

	if !plugin.enabled {
		log.Printf("Plugin %v is already disabled. Ignoring", pluginID)
		return false
	}
	log.Printf("Disabling plugin %v...", pluginID)

	var bundle *policy.PolicyBundle
	if bundle = e.Fetch(); bundle == nil {
		log.Print("Error loading enforcer policies")
		return false
	}

	for _, p := range bundle.Filter(pluginFilter(plugin)) {
		for _, content := range p.CContents {
			if content.PluginID == plugin.ID() {
				log.Printf("Removing policy: %v...", p.Description)
				plugin.Remove(p.UUID)
			}
		}
	}

	plugin.enabled = false
	return true
}

// Implementation of the Plugin API

// pluginFilter returns a predicate that can be used to filter policies
// that apply to the given plugin
func pluginFilter(plugin Plugin) policy.PolicyPredicate {
	return func(p *policy.Policy) bool {
		if p.CContents != nil {
			for _, content := range p.CContents {
				if content.PluginID == plugin.ID() {
					return true
				}
			}
		}
		return false
	}
}

// RegisterPlugin adds the given plugin to this enforcer
func (e *Enforcer) RegisterPlugin(plugin Plugin) bool {
	id := plugin.ID()
	log.Printf("Registering plugin %v...", id)
	if p, registered := e.RegisteredPlugins[id]; registered {
		log.Printf("Error registering plugin %v. A plugin with id %v already exists: %v", plugin, id, p)
		return false
	}

	log.Printf("Applying policies to plugin %v...", id)
	e.RegisteredPlugins[id] = &loadedPlugin{plugin, false}
	e.Enable(id)
	return true
}

// UnregisterPlugin removes the given plugin from this enforcer
func (e *Enforcer) UnregisterPlugin(plugin Plugin) bool {
	id := plugin.ID()
	log.Printf("Unregistering plugin %v...", id)

	var disabled bool
	if disabled = e.Disable(id); !disabled {
		log.Printf("Error disabling plugin %v before unregistering", id)
	}

	_, unregistered := e.RegisteredPlugins[id]
	delete(e.RegisteredPlugins, id)
	return unregistered
}
