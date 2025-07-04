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

package api

import (
	"fmt"
)

// Column is an interface for printing columns
type column interface {
	header() string
	value(output *Output) string
}

type columnList map[int]column

// PossibleColumnNames is the list of implmented columns
var PossibleColumnNames = []string{
	"NAME",
	"FILEPATH",
	"NAMESPACE",
	"KIND",
	"VERSION",
	"REPLACEMENT",
	"DEPRECATED",
	"DEPRECATED IN",
	"REMOVED",
	"REMOVED IN",
	"COMPONENT",
	"REPL AVAIL",
	"REPL AVAIL IN",
	"CELS",
	"MESSAGES",
	"FIELDS",
}

var possibleColumns = []column{
	new(name),
	new(namespace),
	new(kind),
	new(version),
	new(replacement),
	new(deprecated),
	new(deprecatedIn),
	new(removed),
	new(removedIn),
	new(component),
	new(filepath),
	new(replacementAvailable),
	new(replacementAvailableIn),
	new(cels),
	new(messages),
	new(field),
}

// name is the output name
type name struct{}

func (n name) header() string              { return "NAME" }
func (n name) value(output *Output) string { return output.Name }

// filepath is the full path of the file
type filepath struct{}

func (f filepath) header() string { return "FILEPATH" }
func (f filepath) value(output *Output) string {
	if output.FilePath == "" {
		return "<UNKNOWN>"
	}
	return output.FilePath
}

// namespace is the output namespace if available
type namespace struct{}

func (ns namespace) header() string { return "NAMESPACE" }
func (ns namespace) value(output *Output) string {
	if output.Namespace == "" {
		return "<UNKNOWN>"
	}
	return output.Namespace
}

// kind is the output apiVersion kind
type kind struct{}

func (k kind) header() string              { return "KIND" }
func (k kind) value(output *Output) string { return output.APIVersion.Kind }

// version is the output apiVersion
type version struct{}

func (v version) header() string              { return "VERSION" }
func (v version) value(output *Output) string { return output.APIVersion.Name }

// replacement is the output replacement apiVersion
type replacement struct{}

func (r replacement) header() string              { return "REPLACEMENT" }
func (r replacement) value(output *Output) string { return output.APIVersion.ReplacementAPI }

// deprecated is the output for the boolean Deprecated
type deprecated struct{}

func (d deprecated) header() string              { return "DEPRECATED" }
func (d deprecated) value(output *Output) string { return fmt.Sprintf("%t", output.Deprecated) }

// removed is the output for the boolean Deprecated
type removed struct{}

func (r removed) header() string              { return "REMOVED" }
func (r removed) value(output *Output) string { return fmt.Sprintf("%t", output.Removed) }

// deprecatedIn is the string value of when an output was deprecated
type deprecatedIn struct{}

func (di deprecatedIn) header() string              { return "DEPRECATED IN" }
func (di deprecatedIn) value(output *Output) string { return output.APIVersion.DeprecatedIn }

// removedIn is the string value of when an output was deprecated
type removedIn struct{}

func (ri removedIn) header() string              { return "REMOVED IN" }
func (ri removedIn) value(output *Output) string { return output.APIVersion.RemovedIn }

// component is the component that the deprecation came from
type component struct{}

func (c component) header() string              { return "COMPONENT" }
func (c component) value(output *Output) string { return output.APIVersion.Component }

// replacementAvailable is the output for the boolean ReplacementAvailable
type replacementAvailable struct{}

func (ra replacementAvailable) header() string { return "REPL AVAIL" }
func (ra replacementAvailable) value(output *Output) string {
	return fmt.Sprintf("%t", output.ReplacementAvailable)
}

// replacementAvailableIn is the string value of when an output was ReplacementAvailableIn
type replacementAvailableIn struct{}

func (rai replacementAvailableIn) header() string { return "REPL AVAIL IN" }
func (rai replacementAvailableIn) value(output *Output) string {
	return output.APIVersion.ReplacementAvailableIn
}

type cels struct{}

func (cs cels) header() string { return "CELS" }
func (cs cels) value(output *Output) string {
	return fmt.Sprintf("[%v]", output.Cels)
}

type messages struct{}

func (ms messages) header() string { return "Messages" }
func (ms messages) value(output *Output) string {
	return fmt.Sprintf("[%s]", output.Messages)
}

type field struct{}

func (ms field) header() string { return "FIELDS" }
func (ms field) value(output *Output) string {
	return fmt.Sprintf("[%+v]", output.FieldVersions)
}

// normalColumns returns the list of columns for -onormal
func (instance *Instance) normalColumns() columnList {
	columnList := columnList{
		0: new(name),
		1: new(kind),
		2: new(version),
		3: new(replacement),
		4: new(removed),
		5: new(deprecated),
		6: new(replacementAvailable),
		7: new(cels),
		8: new(messages),
		9: new(field),
	}
	return columnList
}

// wideColumns returns the list of columns for -owide
func (instance *Instance) wideColumns() columnList {
	columnList := columnList{
		0:  new(name),
		1:  new(namespace),
		2:  new(kind),
		3:  new(version),
		4:  new(replacement),
		5:  new(deprecated),
		6:  new(deprecatedIn),
		7:  new(removed),
		8:  new(removedIn),
		9:  new(replacementAvailable),
		10: new(replacementAvailableIn),
		11: new(cels),
		12: new(messages),
		13: new(field),
	}
	return columnList
}

// customColumns returns a custom list of columns based on names
func (instance *Instance) customColumns() columnList {
	outputColumns := make(map[int]column)
	for i, d := range instance.CustomColumns {
		for _, c := range possibleColumns {
			if d == c.header() {
				outputColumns[i] = c
			}
		}
	}
	return outputColumns
}
