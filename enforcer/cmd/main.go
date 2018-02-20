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
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"
	"github.com/padmeio/padme/enforcer"
	"github.com/padmeio/padme/enforcer/cmd/controllers"
	store "github.com/padmeio/padme/enforcer/store/filesystem"
)

func main() {
	var policyRepositoryFile, serverAddr string
	flag.StringVar(&policyRepositoryFile, "policy-repo", "/opt/padme-policies.json", "Policy repository file")
	flag.StringVar(&serverAddr, "addr", ":8000", "Server address")
	flag.Parse()

	store := &store.LocalPolicyRepository{FilePath: policyRepositoryFile}
	enforcer := enforcer.NewEnforcer(store)

	router := mux.NewRouter()
	controllers.Init(&enforcer)
	controllers.ConfigurePolicyRoutes(router)

	log.Printf("Starting Enforcer server on %v...", serverAddr)
	server := &http.Server{Addr: serverAddr, Handler: router}
	go func() { log.Fatal(server.ListenAndServe()) }()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	log.Printf("Shutdown signal received. Shutting down gracefully...")
	server.Shutdown(context.Background())
}
