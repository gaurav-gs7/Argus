package topology

import (
	"sort"
	"time"
)

type Dependency struct {
	ID             string    `json:"id"`
	ServiceID      string    `json:"service_id"`
	Service        string    `json:"service"`
	DependsOnID    string    `json:"depends_on_service_id"`
	DependsOn      string    `json:"depends_on_service"`
	DependencyType string    `json:"dependency_type"`
	Criticality    string    `json:"criticality"`
	CreatedAt      time.Time `json:"created_at,omitempty"`
}

type Path struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Services []string `json:"services"`
}

type Group struct {
	Root        string          `json:"root"`
	Environment string          `json:"environment,omitempty"`
	Inferred    bool            `json:"inferred"`
	Members     []string        `json:"members"`
	Paths       map[string]Path `json:"paths"`
}

type Graph struct {
	dependencies map[string][]string
	services     map[string]struct{}
}

func New(edges []Dependency) *Graph {
	graph := &Graph{
		dependencies: make(map[string][]string),
		services:     make(map[string]struct{}),
	}
	for _, edge := range edges {
		if edge.Service == "" || edge.DependsOn == "" || edge.Service == edge.DependsOn {
			continue
		}
		graph.services[edge.Service] = struct{}{}
		graph.services[edge.DependsOn] = struct{}{}
		graph.dependencies[edge.Service] = appendUnique(graph.dependencies[edge.Service], edge.DependsOn)
	}
	for service := range graph.dependencies {
		sort.Strings(graph.dependencies[service])
	}
	return graph
}

func (g *Graph) Path(service, dependency string) (Path, bool) {
	if service == "" || dependency == "" {
		return Path{}, false
	}
	if service == dependency {
		return Path{From: service, To: dependency, Services: []string{service}}, true
	}

	type candidate struct {
		service string
		path    []string
	}
	queue := []candidate{{service: service, path: []string{service}}}
	visited := map[string]struct{}{service: {}}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, next := range g.dependencies[current.service] {
			if _, seen := visited[next]; seen {
				continue
			}
			path := append(append([]string(nil), current.path...), next)
			if next == dependency {
				return Path{From: service, To: dependency, Services: path}, true
			}
			visited[next] = struct{}{}
			queue = append(queue, candidate{service: next, path: path})
		}
	}
	return Path{}, false
}

func (g *Graph) Groups(services []string) []Group {
	alerted := uniqueSorted(services)
	unassigned := make(map[string]struct{}, len(alerted))
	alertedSet := make(map[string]struct{}, len(alerted))
	for _, service := range alerted {
		unassigned[service] = struct{}{}
		alertedSet[service] = struct{}{}
	}

	var groups []Group
	for len(unassigned) > 0 {
		candidates := g.rootCandidates(unassigned)
		bestRoot := ""
		var bestMembers []string
		bestDistance := 0
		bestAlerted := false

		for _, root := range candidates {
			members, distance := g.covered(root, unassigned)
			if len(members) == 0 {
				continue
			}
			_, rootAlerted := alertedSet[root]
			if betterRoot(root, members, distance, rootAlerted, bestRoot, bestMembers, bestDistance, bestAlerted) {
				bestRoot = root
				bestMembers = members
				bestDistance = distance
				bestAlerted = rootAlerted
			}
		}

		if bestRoot == "" {
			bestRoot = firstKey(unassigned)
			bestMembers = []string{bestRoot}
			bestAlerted = true
		}
		paths := make(map[string]Path, len(bestMembers))
		for _, member := range bestMembers {
			path, _ := g.Path(member, bestRoot)
			paths[member] = path
			delete(unassigned, member)
		}
		groups = append(groups, Group{
			Root:     bestRoot,
			Inferred: !bestAlerted,
			Members:  bestMembers,
			Paths:    paths,
		})
	}

	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Root < groups[j].Root })
	return groups
}

func (g *Graph) rootCandidates(services map[string]struct{}) []string {
	candidates := make(map[string]struct{})
	for service := range services {
		candidates[service] = struct{}{}
		queue := []string{service}
		visited := map[string]struct{}{service: {}}
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			for _, dependency := range g.dependencies[current] {
				if _, seen := visited[dependency]; seen {
					continue
				}
				visited[dependency] = struct{}{}
				candidates[dependency] = struct{}{}
				queue = append(queue, dependency)
			}
		}
	}
	return sortedKeys(candidates)
}

func (g *Graph) covered(root string, services map[string]struct{}) ([]string, int) {
	var members []string
	totalDistance := 0
	for service := range services {
		path, ok := g.Path(service, root)
		if !ok {
			continue
		}
		members = append(members, service)
		totalDistance += len(path.Services) - 1
	}
	sort.Strings(members)
	return members, totalDistance
}

func betterRoot(
	root string,
	members []string,
	distance int,
	rootAlerted bool,
	bestRoot string,
	bestMembers []string,
	bestDistance int,
	bestAlerted bool,
) bool {
	if len(members) != len(bestMembers) {
		return len(members) > len(bestMembers)
	}
	if distance != bestDistance {
		return distance < bestDistance
	}
	if rootAlerted != bestAlerted {
		return rootAlerted
	}
	return bestRoot == "" || root < bestRoot
}

func uniqueSorted(values []string) []string {
	items := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			items[value] = struct{}{}
		}
	}
	return sortedKeys(items)
}

func sortedKeys(values map[string]struct{}) []string {
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Strings(items)
	return items
}

func firstKey(values map[string]struct{}) string {
	keys := sortedKeys(values)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
