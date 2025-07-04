// Copyright 2022 FairwindsOps Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Copyright 2020 Fairwinds
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
// limitations under the License

package discoveryapi

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/fairwindsops/pluto/v5/pkg/api"
	"github.com/fairwindsops/pluto/v5/pkg/kube"
)

// DiscoveryClient is the declaration to hold objects needed for client-go/discovery.
type DiscoveryResourceFieldClient struct {
	ClientSet       dynamic.Interface
	restConfig      *rest.Config
	DiscoveryClient discovery.DiscoveryInterface
	Instance        *api.Instance
	ResourcesName   sets.Set[string]
	namespace       string
}

// NewDiscoveryClient returns a new struct with config portions complete.
func NewDiscoveryResourceFieldClient(namespace string, kubeContext string, instance *api.Instance, kubeConfigPath string, ResourcesName sets.Set[string]) (*DiscoveryResourceFieldClient, error) {
	cl := &DiscoveryResourceFieldClient{
		Instance:      instance,
		ResourcesName: ResourcesName,
	}

	var err error
	cl.restConfig, err = kube.GetConfig(kubeContext, kubeConfigPath)
	if err != nil {
		return nil, err
	}

	if cl.DiscoveryClient, err = discovery.NewDiscoveryClientForConfig(cl.restConfig); err != nil {
		return nil, err
	}

	cl.namespace = namespace

	cl.ClientSet, err = dynamic.NewForConfig(cl.restConfig)
	if err != nil {
		return nil, err
	}

	return cl, nil
}

// GetApiResources discovers the api-resources for a cluster
func (cl *DiscoveryResourceFieldClient) GetApiResources() error {
	resourcelist, err := cl.DiscoveryClient.ServerPreferredResources()
	if err != nil {
		if apierrors.IsNotFound(err) {
			return err
		}
		if apierrors.IsForbidden(err) {
			klog.Error("Failed to list objects for Name discovery. Permission denied! Please check if you have the proper authorization")
			return err
		}
	}

	klog.V(2).Info("wait watch resource set %v", cl.ResourcesName)

	gvrs := []schema.GroupVersionResource{}
	for _, rl := range resourcelist {
		for i := range rl.APIResources {
			if cl.namespace != "" && !rl.APIResources[i].Namespaced {
				continue
			}
			gv, _ := schema.ParseGroupVersion(rl.GroupVersion)
			ResourceName := rl.APIResources[i].Name
			if !cl.ResourcesName.Has(ResourceName) {
				continue
			}
			g := schema.GroupVersionResource{Group: gv.Group, Version: gv.Version, Resource: ResourceName}
			gvrs = append(gvrs, g)
		}
	}

	var results []map[string]interface{}
	for _, g := range gvrs {
		nri := cl.ClientSet.Resource(g)
		var ri dynamic.ResourceInterface = nri
		if cl.namespace != "" {
			ri = nri.Namespace(cl.namespace)
		}
		klog.V(2).Infof("Field Retrieving : %s.%s.%s", g.Resource, g.Version, g.Group)
		rs, err := ri.List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			klog.V(2).Info("Failed to retrieve: ", g, err)
			continue
		}

		if len(rs.Items) == 0 {
			klog.V(2).Infof("No data for ResourceVer %s", rs.GetAPIVersion())
			continue

		} else {
			for _, r := range rs.Items {
				output, err := cl.Instance.IsVersionField(r.Object, r.Object["kind"].(string))
				if err != nil {
					return err
				}
				cl.Instance.Outputs = append(cl.Instance.Outputs, output...)
			}
		}
	}

	klog.V(6).Infof("Result from resources: %d", len(results))
	return nil
}
