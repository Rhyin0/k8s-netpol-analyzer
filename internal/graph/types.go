package graph

// NetworkPolicy YAML 结构定义
type NetworkPolicy struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

type Spec struct {
	PodSelector PodSelector   `yaml:"podSelector"`
	PolicyTypes []string      `yaml:"policyTypes"`
	Ingress     []IngressRule `yaml:"ingress"`
	Egress      []EgressRule  `yaml:"egress"`
}

type PodSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels"`
}

type IngressRule struct {
	From  []Peer     `yaml:"from"`
	Ports []PortRule `yaml:"ports"`
}

type EgressRule struct {
	To    []Peer     `yaml:"to"`
	Ports []PortRule `yaml:"ports"`
}

type Peer struct {
	PodSelector PodSelector `yaml:"podSelector"`
}

type PortRule struct {
	Protocol string `yaml:"protocol"`
	Port     int    `yaml:"port"`
}

// 有向图：表示 Pod 之间的可达性
type Edge struct {
	From     string
	To       string
	Port     int
	Protocol string
}
