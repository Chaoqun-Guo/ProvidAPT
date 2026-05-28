package provenance

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// JSON serializer (PROV-JSON format)
// ═══════════════════════════════════════════════════════════════

// provJSON mirrors the W3C PROV-JSON structure.
type provJSON struct {
	Prefix         map[string]string              `json:"prefix"`
	Activity       map[string]provElement         `json:"activity,omitempty"`
	Entity         map[string]provElement         `json:"entity,omitempty"`
	Agent          map[string]provElement         `json:"agent,omitempty"`

	// Relations — field names match PROV-JSON section keys exactly.
	Used           []provActivityEntity           `json:"used,omitempty"`
	WasGeneratedBy []provActivityEntity           `json:"wasGeneratedBy,omitempty"`
	WasInformedBy  []provInformedBy               `json:"wasInformedBy,omitempty"`
}

type provElement struct {
	ProvType  string                 `json:"prov:type"`
	ProvLabel string                 `json:"prov:label,omitempty"`
	Extra     map[string]interface{} `json:"-"`
}

// MarshalJSON implements custom marshalling so that extra attributes
// are folded into the same object as the standard PROV fields.
func (e provElement) MarshalJSON() ([]byte, error) {
	base := map[string]interface{}{
		"prov:type": e.ProvType,
	}
	if e.ProvLabel != "" {
		base["prov:label"] = e.ProvLabel
	}
	for k, v := range e.Extra {
		base[k] = v
	}
	return json.Marshal(base)
}

// provActivityEntity is used for used/ wasGeneratedBy, which take
// prov:activity + prov:entity.
type provActivityEntity struct {
	Activity string `json:"prov:activity"`
	Entity   string `json:"prov:entity"`
	Time     string `json:"prov:time,omitempty"`
	Count    int    `json:"count,omitempty"`
}

// provInformedBy is used for wasInformedBy, which takes
// prov:informed + prov:informant (both activities).
type provInformedBy struct {
	Informed  string `json:"prov:informed"`
	Informant string `json:"prov:informant"`
	Time      string `json:"prov:time,omitempty"`
	Count     int    `json:"count,omitempty"`
}

const provTimeFormat = time.RFC3339Nano

// SerializeJSON writes the provenance graph in PROV-JSON format.
func (g *Graph) SerializeJSON(w io.Writer) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	root := provJSON{
		Prefix: map[string]string{
			"prov": ProvNamespace,
		},
		Activity:       make(map[string]provElement),
		Entity:         make(map[string]provElement),
		Used:           make([]provActivityEntity, 0),
		WasGeneratedBy: make([]provActivityEntity, 0),
		WasInformedBy:  make([]provInformedBy, 0),
	}

	// Partition nodes into PROV buckets
	for _, n := range g.nodes {
		el := provElement{
			ProvType:  n.ProvType,
			ProvLabel: n.Label,
			Extra:     make(map[string]interface{}),
		}
		for k, v := range n.Attributes {
			el.Extra[k] = v
		}
		el.Extra["subtype"] = n.Subtype

		switch n.ProvType {
		case ProvActivity:
			root.Activity[n.ID] = el
		case ProvEntity:
			root.Entity[n.ID] = el
		case ProvAgent:
			root.Agent[n.ID] = el
		}
	}

	// Partition edges into PROV buckets
	for _, e := range g.edges {
		ts := e.Timestamp.Format(provTimeFormat)

		switch e.Relation {
		case ProvUsed:
			root.Used = append(root.Used, provActivityEntity{
				Activity: e.Source, // process
				Entity:   e.Target, // file
				Time:     ts,
				Count:    e.Count,
			})
		case ProvWasGeneratedBy:
			root.WasGeneratedBy = append(root.WasGeneratedBy, provActivityEntity{
				Activity: e.Target, // process (the generator)
				Entity:   e.Source, // file (the generated)
				Time:     ts,
				Count:    e.Count,
			})
		case ProvWasInformedBy:
			root.WasInformedBy = append(root.WasInformedBy, provInformedBy{
				Informed:  e.Source,   // child activity
				Informant: e.Target,   // parent activity
				Time:      ts,
				Count:     e.Count,
			})
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(root)
}

// ═══════════════════════════════════════════════════════════════
// GraphML serializer (used by yEd, Gephi, Cytoscape, etc.)
// ═══════════════════════════════════════════════════════════════

type graphmlRoot struct {
	XMLName xml.Name      `xml:"graphml"`
	Xmlns   string        `xml:"xmlns,attr"`
	Keys    []graphmlKey  `xml:"key"`
	Graph   graphmlGraph  `xml:"graph"`
}

type graphmlKey struct {
	ID       string `xml:"id,attr"`
	For      string `xml:"for,attr"`
	AttrName string `xml:"attr.name,attr"`
	AttrType string `xml:"attr.type,attr"`
}

type graphmlGraph struct {
	ID          string         `xml:"id,attr"`
	EdgeDefault string         `xml:"edgedefault,attr"`
	Nodes       []graphmlNode  `xml:"node"`
	Edges       []graphmlEdge  `xml:"edge"`
}

type graphmlNode struct {
	ID    string        `xml:"id,attr"`
	Datas []graphmlData `xml:"data"`
}

type graphmlEdge struct {
	ID     string        `xml:"id,attr"`
	Source string        `xml:"source,attr"`
	Target string        `xml:"target,attr"`
	Datas  []graphmlData `xml:"data"`
}

type graphmlData struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// SerializeGraphML writes the provenance graph in GraphML format,
// compatible with yEd, Gephi, and Cytoscape.
func (g *Graph) SerializeGraphML(w io.Writer) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Write XML declaration manually; encoding/xml omits it.
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}

	root := graphmlRoot{
		Xmlns: "http://graphml.graphdrawing.org/xmlns",
		Keys: []graphmlKey{
			{ID: "prov_type", For: "node", AttrName: "prov_type", AttrType: "string"},
			{ID: "subtype", For: "node", AttrName: "subtype", AttrType: "string"},
			{ID: "label", For: "node", AttrName: "label", AttrType: "string"},
			{ID: "pid", For: "node", AttrName: "pid", AttrType: "int"},
			{ID: "uid", For: "node", AttrName: "uid", AttrType: "int"},
			{ID: "inode", For: "node", AttrName: "inode", AttrType: "long"},
			{ID: "relation", For: "edge", AttrName: "relation", AttrType: "string"},
			{ID: "count", For: "edge", AttrName: "count", AttrType: "int"},
			{ID: "timestamp", For: "edge", AttrName: "timestamp", AttrType: "string"},
		},
		Graph: graphmlGraph{
			ID:          "provenance",
			EdgeDefault: "directed",
			Nodes:       make([]graphmlNode, 0, len(g.nodes)),
			Edges:       make([]graphmlEdge, 0, len(g.edges)),
		},
	}

	for _, n := range g.nodes {
		datas := []graphmlData{
			{Key: "prov_type", Value: n.ProvType},
			{Key: "subtype", Value: n.Subtype},
			{Key: "label", Value: n.Label},
		}
		if v, ok := n.Attributes["pid"]; ok {
			datas = append(datas, graphmlData{Key: "pid", Value: fmt.Sprint(v)})
		}
		if v, ok := n.Attributes["uid"]; ok {
			datas = append(datas, graphmlData{Key: "uid", Value: fmt.Sprint(v)})
		}
		if v, ok := n.Attributes["inode"]; ok {
			datas = append(datas, graphmlData{Key: "inode", Value: fmt.Sprint(v)})
		}
		root.Graph.Nodes = append(root.Graph.Nodes, graphmlNode{
			ID:    n.ID,
			Datas: datas,
		})
	}

	for _, e := range g.edges {
		datas := []graphmlData{
			{Key: "relation", Value: e.Relation},
			{Key: "count", Value: fmt.Sprint(e.Count)},
			{Key: "timestamp", Value: e.Timestamp.Format(provTimeFormat)},
		}
		root.Graph.Edges = append(root.Graph.Edges, graphmlEdge{
			ID:     e.ID,
			Source: e.Source,
			Target: e.Target,
			Datas:  datas,
		})
	}

	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(root); err != nil {
		return fmt.Errorf("graphml encode: %w", err)
	}
	// Write final newline
	_, err := fmt.Fprintln(w)
	return err
}

// ═══════════════════════════════════════════════════════════════
// Compact JSON (one event per line, suitable for streaming)
// ═══════════════════════════════════════════════════════════════

// SerializeEdgeJSON writes a single edge as a compact JSON line.
// Useful for streaming large graphs without holding everything in memory.
func (e *Edge) SerializeEdgeJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	return enc.Encode(map[string]interface{}{
		"id":        e.ID,
		"relation":  e.Relation,
		"source":    e.Source,
		"target":    e.Target,
		"timestamp": e.Timestamp.UnixNano(),
		"count":     e.Count,
	})
}
