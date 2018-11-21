// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/maps/policymap/policykey"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

var (
	// localHostKey represents an ingress L3 allow from the local host.
	localHostKey = policykey.PolicyKey{
		Identity:         identity.ReservedIdentityHost.Uint32(),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}

	// worldKey represents an ingress L3 allow from the world.
	worldKey = policykey.PolicyKey{
		Identity:         identity.ReservedIdentityWorld.Uint32(),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}
)

// PolicyMapState is a state of a policy map.
type PolicyMapState map[policykey.PolicyKey]PolicyMapStateEntry

// PolicyMapStateEntry is the configuration associated with a PolicyKey in a
// PolicyMapState. This is a minimized version of policymap.PolicyEntry.
type PolicyMapStateEntry struct {
	// The proxy port, in host byte order.
	// If 0 (default), there is no proxy redirection for the corresponding
	// PolicyKey.
	ProxyPort uint16
}

func (keys PolicyMapState) DetermineAllowFromWorld() {

	_, localHostAllowed := keys[localHostKey]
	if option.Config.HostAllowsWorld && localHostAllowed {
		keys[worldKey] = PolicyMapStateEntry{}
	}
}

// determineAllowLocalhost determines whether communication should be allowed to
// the localhost. It inserts the PolicyKey corresponding to the localhost in
// the desiredPolicyKeys if the endpoint is allowed to communicate with the
// localhost.
func (keys PolicyMapState) DetermineAllowLocalhost(l4Policy *L4Policy) {

	if option.Config.AlwaysAllowLocalhost() || (l4Policy != nil && l4Policy.HasRedirect()) {
		keys[localHostKey] = PolicyMapStateEntry{}
	}
}
