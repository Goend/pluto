package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

const k8scomponent string = "k8s"

// VersionField represents a deprecated or removed field definition
type VersionField struct {
	Name                   string          `yaml:"name"`
	Kind                   string          `yaml:"kind"`
	Resource               string          `yaml:"resource"`
	Match                  MatchExpression `yaml:"match"`
	Message                string          `yaml:"message"`
	DeprecatedIn           string          `yaml:"deprecated-in,omitempty"`
	RemovedIn              string          `yaml:"removed-in,omitempty"`
	ReplacementField       string          `yaml:"replacement-field,omitempty"`
	ReplacementAvailableIn string          `yaml:"replacement-available-in,omitempty"`
}

type VersionFieldStatus struct {
	// Deprecated is a boolean indicating whether or not the version is deprecated
	Deprecated bool `json:"deprecated" yaml:"deprecated"`
	// DeprecatedIn is a string that indicates what version the api is deprecated in
	// an empty string indicates that the version is not deprecated
	DeprecatedIn string `json:"deprecated-in" yaml:"deprecated-in"`
	// Removed is a boolean indicating whether or not the version has been removed
	Removed bool `json:"removed" yaml:"removed"`
	// RemovedIn denotes the version that the api was actually removed in
	// An empty string indicates that the version has not been removed yet
	RemovedIn string `json:"removed-in" yaml:"removed-in"`
	// ReplacementAvailable is a boolean indicating whether or not the replacement is available
	ReplacementAvailable bool `json:"replacementAvailable" yaml:"replacementAvailable"`
	// ReplacementAPI is the apiVersion that replaces the deprecated one
	ReplacementAPI string `json:"replacement-api" yaml:"replacement-api"`
	// ReplacementAvailableIn is the version in which the replacement api is available
	ReplacementAvailableIn string `json:"replacement-available-in" yaml:"replacement-available-in"`
}

// MatchExpression contains the matching rule expression
type MatchExpression struct {
	Expression string `yaml:"expression"`
}

type VersionFields []VersionField

// NewVersionFieldsFromYAML parses YAML data into a slice of VersionField
func NewVersionFieldsFromYAML(data []byte) (VersionFields, error) {
	var fields VersionFields
	if err := yaml.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("failed to unmarshal version fields: %w", err)
	}

	for i := range fields {
		if err := fields[i].Validate(); err != nil {
			return nil, fmt.Errorf("invalid field definition at index %d: %w", i, err)
		}
	}

	return fields, nil
}

// Validate checks required fields in VersionField
func (vf *VersionField) Validate() error {
	if vf.Name == "" {
		return errors.New("name is required")
	}
	if vf.Kind == "" {
		return errors.New("kind is required")
	}
	if vf.Match.Expression == "" {
		return errors.New("match expression is required")
	}

	if vf.Message == "" {
		return errors.New("message is required")
	}
	return nil
}

// GetFieldsByKind 返回指定Kind类型的所有规则
func GetFieldsByKind(vfs VersionFields, kind string) []VersionField {
	var result []VersionField
	for fk, field := range vfs {
		if field.Kind == kind {
			result = append(result, vfs[fk])
		}
	}
	return result
}

func (vfs *VersionFields) GetFieldAllResources() sets.Set[string] {
	resourceSet := sets.New[string]()
	for _, field := range *vfs {
		resourceSet.Insert(field.Resource)
	}
	return resourceSet
}

func compile(env *cel.Env, expr string, celType *cel.Type) *cel.Ast {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		klog.Fatal(iss.Err())
	}
	if !reflect.DeepEqual(ast.OutputType(), celType) {
		klog.Fatalf("Got %v, wanted %v result type", ast.OutputType(), celType)
	}
	return ast
}

func eval(prg cel.Program, vars any) (out ref.Val, err error) {
	varMap, isMap := vars.(map[string]any)
	if !isMap {
		fmt.Printf("(%T)\n", vars)
	} else {
		for k, v := range varMap {
			switch val := v.(type) {
			case map[string]any:
				klog.V(5).Info(val)
				b, _ := json.MarshalIndent(v, "", "  ")
				klog.V(2).Infof("%s = %v\n", k, string(b))
			case uint64:
				fmt.Printf("%s = %vu\n", k, v)
				klog.V(2).Infof("%s = %vu\n", k, v)
			default:
				klog.V(2).Infof("%s = %v\n", k, v)
			}
		}
	}
	eval, det, err := prg.Eval(vars)
	klog.V(2).Infof("cel det %v", det)
	if err != nil {
		return nil, err
	}

	return eval, nil
}

// ValidateWithCEL 验证非结构化对象是否匹配CEL表达式
func (vf *VersionField) ValidateWithCEL(obj map[string]interface{}) (bool, error) {
	klog.V(5).Infof("obj %v", obj)

	env, _ := cel.NewEnv(
		cel.Variable("object", cel.MapType(cel.StringType, cel.DynType)),
	)

	ast := compile(env, vf.Match.Expression, cel.BoolType)

	program, _ := env.Program(ast)

	// Evaluate a complex-ish JWT with two groups that satisfy the criteria.
	// Output: true.
	validated, err := eval(program,
		map[string]interface{}{
			"object": obj,
		})

	if err != nil {
		return false, err
	}

	result, ok := validated.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL expression did not return boolean")
	}

	return result, nil

}

func (instance *Instance) IsVersionField(data map[string]interface{}, kind string) ([]*Output, error) {
	var outputs []*Output

	if data != nil {
		fields := GetFieldsByKind(instance.DeprecatedField, kind)
		for key, field := range fields {
			var f VersionFieldStatus
			f = instance.checkVersionField(fields[key])
			if f.Deprecated || f.Removed {
				var output Output
				check, err := field.ValidateWithCEL(data)
				if err != nil {
					return nil, err
				}
				metadata := data["metadata"].(map[string]interface{})
				klog.V(5).Infof("validate CEL %s with kind %s,resource is %s", field.Name, kind, metadata["name"].(string))
				// check black list
				if check {
					output.Name = metadata["name"].(string)
					fakeVersion := new(Version)
					fakeVersion.Kind = kind
					fakeVersion.Name = data["apiVersion"].(string)
					output.APIVersion = fakeVersion
					output.Namespace = metadata["namespace"].(string)
					output.FieldVersions = f
					output.Cels = fields[key].Match
					output.Messages = fields[key].Message
					outputs = append(outputs, &output)
				}
			}
		}
	}
	return outputs, nil
}

func (instance *Instance) checkVersionField(field VersionField) VersionFieldStatus {
	var fieldStatus VersionFieldStatus
	targetVersion, ok := instance.TargetVersions[k8scomponent]
	if !ok {
		klog.V(3).Infof("targetVersion missing for kind %s", field.Kind)
		return fieldStatus
	}

	if !semver.IsValid(targetVersion) {
		klog.V(3).Infof("targetVersion %s is not valid semVer", targetVersion)
		return fieldStatus
	}

	// 设置弃用信息
	if field.DeprecatedIn != "" {
		fieldStatus.Deprecated = semver.Compare(targetVersion, field.DeprecatedIn) >= 0
		fieldStatus.DeprecatedIn = field.DeprecatedIn
	}

	// 设置移除信息
	if field.RemovedIn != "" {
		fieldStatus.Removed = semver.Compare(targetVersion, field.RemovedIn) >= 0
		fieldStatus.RemovedIn = field.RemovedIn
	}

	// 设置替代信息
	if field.ReplacementAvailableIn != "" {
		fieldStatus.ReplacementAvailable = semver.Compare(targetVersion, field.ReplacementAvailableIn) >= 0
		fieldStatus.ReplacementAvailableIn = field.ReplacementAvailableIn
	}
	fieldStatus.ReplacementAPI = field.ReplacementField

	return fieldStatus
}
