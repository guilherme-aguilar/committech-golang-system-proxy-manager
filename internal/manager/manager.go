package manager

import (
	"log"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/yamux"
)

type ProxyClient struct {
	ID      string
	Session *yamux.Session
}

type Group struct {
	Clients []*ProxyClient
	Counter uint64
}

type GroupManager struct {
	mu     sync.RWMutex
	groups map[string]*Group
}

func New() *GroupManager {
	return &GroupManager{
		groups: make(map[string]*Group),
	}
}

func (m *GroupManager) RegisterClient(clientID, groupName string, s *yamux.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.groups[groupName]; !ok {
		m.groups[groupName] = &Group{}
	}
	g := m.groups[groupName]

	// Remove antigas
	var active []*ProxyClient
	for _, c := range g.Clients {
		if c.ID == clientID {
			c.Session.Close()
		} else if !c.Session.IsClosed() {
			active = append(active, c)
		}
	}
	g.Clients = active
	g.Clients = append(g.Clients, &ProxyClient{ID: clientID, Session: s})

	log.Printf("[Registry] '%s' registrado em '%s'", clientID, groupName)
}

func (m *GroupManager) GetSession(groupName string) *yamux.Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.groups[groupName]
	if !ok || len(g.Clients) == 0 {
		return nil
	}
	idx := atomic.AddUint64(&g.Counter, 1) % uint64(len(g.Clients))
	return g.Clients[idx].Session
}

func (m *GroupManager) GetStatus(groupFilter string) map[string][]map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	report := make(map[string][]map[string]string)

	for name, group := range m.groups {
		if groupFilter != "" && groupFilter != "all" && name != groupFilter {
			continue
		}
		var active []map[string]string
		for _, c := range group.Clients {
			if !c.Session.IsClosed() {
				active = append(active, map[string]string{
					"id":   c.ID,
					"addr": c.Session.RemoteAddr().String(),
				})
			}
		}
		report[name] = active
	}
	return report
}

func (m *GroupManager) ForceDisconnectGroup(groupName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g, ok := m.groups[groupName]; ok {
		for _, c := range g.Clients {
			c.Session.Close()
		}
		delete(m.groups, groupName)
	}
}

func (m *GroupManager) DisconnectClient(groupName, clientID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[groupName]
	if !ok {
		return false
	}

	found := false
	var remaining []*ProxyClient
	for _, c := range g.Clients {
		if c.ID == clientID {
			c.Session.Close()
			found = true
		} else {
			remaining = append(remaining, c)
		}
	}
	g.Clients = remaining
	return found
}
