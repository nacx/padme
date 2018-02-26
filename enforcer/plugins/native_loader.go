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

package plugins

import (
	"fmt"
	"log"
	"plugin"
	"strings"
)

// NativePluginLoader uses the plugin mechanism introduced in Go 1.8 to laod
// compiled plugins from a given directory.
type NativePluginLoader struct {

	// PluginDir is the directory where plugins will be loaded from
	PluginDir string
}

// Load the given plugin using the native plugin support introduced in Go 1.8
//
// Plugins must follow the plugin conventions:
//	- Be present in the configured 'PluginDir/name.so' (plugin name in lowercase)
//	- Must export a variable named 'Name' (the capitalized name of the plugin) of
//	  type 'enforcer.Plugin'
func (l *NativePluginLoader) Load(id string) (Plugin, error) {
	pluginPath := fmt.Sprintf("%v/%v.so", l.PluginDir, id)
	p, err := plugin.Open(pluginPath)
	if err != nil {
		log.Printf("Error loading plugin %v: %v", pluginPath, err)
		return nil, err
	}

	pluginExportedName := strings.Title(id)
	var obj plugin.Symbol
	obj, err = p.Lookup(pluginExportedName)
	if err != nil {
		log.Printf("Error loading plugin %v: %v", pluginExportedName, err)
		return nil, err
	}

	loadedPlugin, ok := obj.(Plugin)
	if !ok {
		return nil, fmt.Errorf("Unexpexted type %T of plugin %v. Expected 'enforcer.Plugin'",
			obj, pluginExportedName)
	}
	return loadedPlugin, nil
}

// Unload releases the resources used by a plugin. In Go 1.8, closing an open
// plugin is still not supported, so this method does nothing.
func (l *NativePluginLoader) Unload(id string) error {
	return nil
}
