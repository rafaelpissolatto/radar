package search

import (
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// fromObject builds a candidate from a typed K8s object. Returns ok=false
// when the object doesn't expose ObjectMeta (shouldn't happen for cache
// objects but we guard anyway).
func fromObject(obj runtime.Object, kind string) (candidate, bool) {
	m, err := meta.Accessor(obj)
	if err != nil {
		return candidate{}, false
	}
	c := candidate{
		Kind:        kind,
		Namespace:   m.GetNamespace(),
		Name:        m.GetName(),
		Labels:      m.GetLabels(),
		Annotations: m.GetAnnotations(),
	}
	c.Images = imagesForTyped(obj)
	return c, true
}

// fromUnstructured builds a candidate from a CRD object. The kind is
// already known by the caller (we don't trust the unstructured's Kind
// since informers strip TypeMeta).
func fromUnstructured(u *unstructured.Unstructured, kind, group string) candidate {
	c := candidate{
		Kind:        kind,
		Group:       group,
		Namespace:   u.GetNamespace(),
		Name:        u.GetName(),
		Labels:      u.GetLabels(),
		Annotations: u.GetAnnotations(),
	}
	c.Images = imagesFromUnstructured(u)
	return c
}

func imagesForTyped(obj runtime.Object) []string {
	switch o := obj.(type) {
	case *corev1.Pod:
		return collectFromPodSpec(&o.Spec)
	case *appsv1.Deployment:
		return collectFromPodSpec(&o.Spec.Template.Spec)
	case *appsv1.DaemonSet:
		return collectFromPodSpec(&o.Spec.Template.Spec)
	case *appsv1.StatefulSet:
		return collectFromPodSpec(&o.Spec.Template.Spec)
	case *appsv1.ReplicaSet:
		return collectFromPodSpec(&o.Spec.Template.Spec)
	case *batchv1.Job:
		return collectFromPodSpec(&o.Spec.Template.Spec)
	case *batchv1.CronJob:
		return collectFromPodSpec(&o.Spec.JobTemplate.Spec.Template.Spec)
	}
	return nil
}

func collectFromPodSpec(spec *corev1.PodSpec) []string {
	if spec == nil {
		return nil
	}
	out := make([]string, 0, len(spec.Containers)+len(spec.InitContainers)+len(spec.EphemeralContainers))
	for _, c := range spec.Containers {
		if c.Image != "" {
			out = append(out, c.Image)
		}
	}
	for _, c := range spec.InitContainers {
		if c.Image != "" {
			out = append(out, c.Image)
		}
	}
	for _, c := range spec.EphemeralContainers {
		if c.Image != "" {
			out = append(out, c.Image)
		}
	}
	return out
}

// imagesFromUnstructured walks common pod-template paths in CRDs.
// We try spec.template.spec.containers first (most workload-shaped CRDs),
// then spec.containers (Pod-shaped), then leave it. Any miss is fine —
// the candidate just won't have images, which only matters for image:
// queries against that CRD.
func imagesFromUnstructured(u *unstructured.Unstructured) []string {
	if u == nil || u.Object == nil {
		return nil
	}
	if imgs := containersAt(u.Object, "spec", "template", "spec"); imgs != nil {
		return imgs
	}
	if imgs := containersAt(u.Object, "spec"); imgs != nil {
		return imgs
	}
	return nil
}

func containersAt(root map[string]any, path ...string) []string {
	cur := root
	for _, k := range path {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	out := imagesFromContainerList(cur["containers"])
	out = append(out, imagesFromContainerList(cur["initContainers"])...)
	if len(out) == 0 {
		return nil
	}
	return out
}

func imagesFromContainerList(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range list {
		c, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if img, ok := c["image"].(string); ok && img != "" {
			out = append(out, img)
		}
	}
	return out
}
