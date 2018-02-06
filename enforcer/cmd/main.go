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

package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/padmeio/padme/enforcer"
	"github.com/padmeio/padme/enforcer/cmd/controllers"
	store "github.com/padmeio/padme/enforcer/store/filesystem"
)

func main() {
	store := store.LocalPolicyStore{}
	enforcer.Store = &store

	flag.StringVar(&store.FilePath, "file", "/tmp/padme-policystore.json", "Policy Store file")
	flag.Parse()

	router := mux.NewRouter()
	controllers.ConfigurePolicyRoutes(router)

	log.Println("Starting Enforcer server on port 8000...")
	http.ListenAndServe(":8000", router)
}
