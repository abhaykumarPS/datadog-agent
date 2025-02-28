// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2017-present Datadog, Inc.

// +build !serverless

package listeners

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strconv"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/common/types"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	v1 "k8s.io/api/core/v1"
)

const (
	// Label keys of Container Autodiscovery
	newIdentifierLabel            = "com.datadoghq.ad.check.id"
	legacyIdentifierLabel         = "com.datadoghq.sd.check.id"
	containerADTemplateCheckNames = "com.datadoghq.ad.check_names"
	// Keys of standard tags
	tagKeyEnv     = "env"
	tagKeyVersion = "version"
	tagKeyService = "service"
)

// containerFilters holds container filters for AD listeners
type containerFilters struct {
	global  *containers.Filter
	metrics *containers.Filter
	logs    *containers.Filter
}

// ComputeContainerServiceIDs takes an entity name, an image (resolved to an actual name) and labels
// and computes the service IDs for this container service.
func ComputeContainerServiceIDs(entity string, image string, labels map[string]string) []string {
	// ID override label
	if l, found := labels[newIdentifierLabel]; found {
		return []string{l}
	}
	if l, found := labels[legacyIdentifierLabel]; found {
		log.Warnf("found legacy %s label for %s, please use the new name %s",
			legacyIdentifierLabel, entity, newIdentifierLabel)
		return []string{l}
	}

	ids := []string{entity}

	// Add Image names (long then short if different)
	long, short, _, err := containers.SplitImageName(image)
	if err != nil {
		log.Warnf("error while spliting image name: %s", err)
	}
	if len(long) > 0 {
		ids = append(ids, long)
	}
	if len(short) > 0 && short != long {
		ids = append(ids, short)
	}
	return ids
}

// getCheckNamesFromLabels unmarshals the json string of check names
// defined in container labels and returns a slice of check names
func getCheckNamesFromLabels(labels map[string]string) ([]string, error) {
	if checkLabels, found := labels[containerADTemplateCheckNames]; found {
		checkNames := []string{}
		err := json.Unmarshal([]byte(checkLabels), &checkNames)
		if err != nil {
			return nil, fmt.Errorf("Cannot parse check names: %v", err)
		}
		return checkNames, nil
	}
	return nil, nil
}

// getStandardTags extract standard tags from labels of kubernetes services
func getStandardTags(labels map[string]string) []string {
	tags := []string{}
	if labels == nil {
		return tags
	}
	labelToTagKeys := map[string]string{
		kubernetes.EnvTagLabelKey:     tagKeyEnv,
		kubernetes.VersionTagLabelKey: tagKeyVersion,
		kubernetes.ServiceTagLabelKey: tagKeyService,
	}
	for labelKey, tagKey := range labelToTagKeys {
		if tagValue, found := labels[labelKey]; found {
			tags = append(tags, fmt.Sprintf("%s:%s", tagKey, tagValue))
		}
	}
	return tags
}

// standardTagsDigest computes the hash of standard tags in a map
func standardTagsDigest(labels map[string]string) string {
	if labels == nil {
		return ""
	}
	h := fnv.New64()
	// the implementation of h.Write never returns a non-nil error
	_, _ = h.Write([]byte(labels[kubernetes.EnvTagLabelKey]))
	_, _ = h.Write([]byte(labels[kubernetes.VersionTagLabelKey]))
	_, _ = h.Write([]byte(labels[kubernetes.ServiceTagLabelKey]))
	return strconv.FormatUint(h.Sum64(), 16)
}

// isServiceAnnotated returns true if the Service has an annotation with a given key
func isServiceAnnotated(ksvc *v1.Service, annotationKey string) bool {
	if ksvc != nil {
		if _, found := ksvc.GetAnnotations()[annotationKey]; found {
			return true
		}
	}
	return false
}

// newContainerFilters instantiates the required container filters for AD listeners
func newContainerFilters() (*containerFilters, error) {
	global, err := containers.NewAutodiscoveryFilter(containers.GlobalFilter)
	if err != nil {
		return nil, err
	}
	metrics, err := containers.NewAutodiscoveryFilter(containers.MetricsFilter)
	if err != nil {
		return nil, err
	}
	logs, err := containers.NewAutodiscoveryFilter(containers.LogsFilter)
	if err != nil {
		return nil, err
	}
	return &containerFilters{
		global:  global,
		metrics: metrics,
		logs:    logs,
	}, nil
}

func (f *containerFilters) IsExcluded(filter containers.FilterType, name, image, ns string) bool {
	switch filter {
	case containers.GlobalFilter:
		return f.global.IsExcluded(name, image, ns)
	case containers.MetricsFilter:
		return f.metrics.IsExcluded(name, image, ns)
	case containers.LogsFilter:
		return f.logs.IsExcluded(name, image, ns)
	}
	return false
}

// getPrometheusIncludeAnnotations returns the Prometheus AD include annotations based on the Prometheus config
func getPrometheusIncludeAnnotations() types.PrometheusAnnotations {
	annotations := types.PrometheusAnnotations{}
	checks := []*types.PrometheusCheck{}
	err := config.Datadog.UnmarshalKey("prometheus_scrape.checks", &checks)
	if err != nil {
		log.Warnf("Couldn't get configurations from 'prometheus_scrape.checks': %v", err)
		return annotations
	}

	if len(checks) == 0 {
		annotations[types.PrometheusScrapeAnnotation] = "true"
		return annotations
	}

	for _, check := range checks {
		if err := check.Init(); err != nil {
			log.Errorf("Couldn't init check configuration: %v", err)
			continue
		}
		for k, v := range check.AD.GetIncludeAnnotations() {
			annotations[k] = v
		}
	}
	return annotations
}
