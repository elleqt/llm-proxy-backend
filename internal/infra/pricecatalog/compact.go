package pricecatalog

import (
	"encoding/json"
	"errors"
	"strconv"
)

var (
	errCompactVersion = errors.New("the catalog uses an unsupported compact format version")
	errCompact        = errors.New("the compact catalog is malformed")
)

// Compact v1 interns objects in nodes; [index] refers to a node. Only model
// costs are decoded, not the unrelated capability, compatibility or array nodes.
// Format: oh-my-pi packages/catalog/src/model-catalog-format.ts.
type compactCatalog struct {
	keys          []string
	booleanShapes [][]int
	nodes         []json.RawMessage
	costs         map[int]*tokenCost
}

func decodeCompact(top map[string]json.RawMessage) (map[string]map[string]entry, error) {
	var version int
	if json.Unmarshal(top["version"], &version) != nil || version != 1 {
		return nil, errCompactVersion
	}

	var (
		catalog   compactCatalog
		providers [][]json.RawMessage
	)
	if json.Unmarshal(top["keys"], &catalog.keys) != nil ||
		json.Unmarshal(top["booleanShapes"], &catalog.booleanShapes) != nil ||
		json.Unmarshal(top["nodes"], &catalog.nodes) != nil ||
		json.Unmarshal(top["providers"], &providers) != nil {
		return nil, errCompact
	}

	catalog.costs = make(map[int]*tokenCost)
	decoded := make(map[string]map[string]entry, len(sections))

	for _, provider := range providers {
		if len(provider) != 3 {
			return nil, errCompact
		}

		var name string
		if json.Unmarshal(provider[0], &name) != nil {
			return nil, errCompact
		}

		for _, sec := range sections {
			if sec.section != name {
				continue
			}

			models, err := catalog.models(provider[2])
			if err != nil {
				return nil, err
			}

			decoded[name] = models

			break
		}
	}

	return decoded, nil
}

func (c *compactCatalog) models(raw json.RawMessage) (map[string]entry, error) {
	var rows [][]json.RawMessage
	if json.Unmarshal(raw, &rows) != nil {
		return nil, errCompact
	}

	models := make(map[string]entry, len(rows))
	for _, row := range rows {
		if len(row) < 2 || len(row) > 3 {
			return nil, errCompact
		}

		var model string
		if json.Unmarshal(row[0], &model) != nil {
			return nil, errCompact
		}

		if !modelID(model) {
			continue
		}

		index, err := c.reference(row[1])
		if err != nil {
			return nil, err
		}

		fields, err := c.priceFields(index)
		if err != nil {
			return nil, err
		}

		var modelEntry entry
		if cost := fields["cost"]; len(cost) > 0 && string(cost) != "null" {
			modelEntry.Cost, err = c.cost(cost)
			if err != nil {
				return nil, err
			}
		}

		models[model] = modelEntry
	}

	return models, nil
}

func (c *compactCatalog) cost(ref json.RawMessage) (*tokenCost, error) {
	index, err := c.reference(ref)
	if err != nil {
		return nil, err
	}

	if cost, ok := c.costs[index]; ok {
		return cost, nil
	}

	fields, err := c.priceFields(index)
	if err != nil {
		return nil, err
	}

	cost := new(tokenCost)

	for name, raw := range fields {
		var dest any

		switch name {
		case "input":
			dest = &cost.Input
		case "output":
			dest = &cost.Output
		case "cacheRead":
			dest = &cost.CacheRead
		case "cacheWrite":
			dest = &cost.CacheWrite
		default:
			continue
		}

		if json.Unmarshal(raw, dest) != nil {
			cost = nil

			break
		}
	}

	c.costs[index] = cost

	return cost, nil
}

func (c *compactCatalog) reference(raw json.RawMessage) (int, error) {
	var ref []json.RawMessage
	if json.Unmarshal(raw, &ref) != nil || len(ref) != 1 {
		return 0, errCompact
	}

	index, err := strconv.Atoi(string(ref[0]))
	if err != nil || index < 0 || index >= len(c.nodes) {
		return 0, errCompact
	}

	return index, nil
}

// priceFields reads one object shallowly. Following only model -> cost keeps
// unrelated nodes out of memory and makes cyclic references unable to recurse.
func (c *compactCatalog) priceFields(index int) (map[string]json.RawMessage, error) {
	var node []json.RawMessage
	if json.Unmarshal(c.nodes[index], &node) != nil || len(node) != 4 || string(node[0]) != "0" {
		return nil, errCompact
	}

	shape, err := strconv.Atoi(string(node[2]))
	if err != nil || shape < 0 || shape >= len(c.booleanShapes) {
		return nil, errCompact
	}

	var (
		properties []json.RawMessage
		masks      []uint32
	)
	if json.Unmarshal(node[1], &properties) != nil || len(properties)%2 != 0 ||
		json.Unmarshal(node[3], &masks) != nil || len(masks) < (len(c.booleanShapes[shape])+31)/32 {
		return nil, errCompact
	}

	fields := make(map[string]json.RawMessage)

	for offset := 0; offset < len(properties); offset += 2 {
		key, err := strconv.Atoi(string(properties[offset]))
		if err != nil || key < 0 || key >= len(c.keys) {
			return nil, errCompact
		}

		if priceField(c.keys[key]) {
			fields[c.keys[key]] = properties[offset+1]
		}
	}

	for bit, key := range c.booleanShapes[shape] {
		if key < 0 || key >= len(c.keys) {
			return nil, errCompact
		}

		if priceField(c.keys[key]) {
			value := "false"
			if masks[bit/32]&(1<<uint(bit%32)) != 0 {
				value = "true"
			}

			fields[c.keys[key]] = json.RawMessage(value)
		}
	}

	return fields, nil
}

func priceField(name string) bool {
	switch name {
	case "cost", "input", "output", "cacheRead", "cacheWrite":
		return true
	default:
		return false
	}
}
