/*
 * Secret Server
 *
 * This is an API of a secret service. You can save your secret by using the API. You can restrict the access of a secret after the certen number of views or after a certen period of time.
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package secrets

import (
	"container/heap"
	"sync"
	"time"
)

type Secret struct {
	doesExpire bool
	index      int
	// Unique hash to identify the secrets
	Hash string `json:"hash"`

	// The secret itself
	SecretText string `json:"secretText"`

	// The date and time of the creation
	CreatedAt time.Time `json:"createdAt"`

	// The secret cannot be reached after this time
	ExpiresAt time.Time `json:"expiresAt"`

	// How many times the secret can be viewed
	RemainingViews int32 `json:"remainingViews"`
}

type PriorityQueue []*Secret

func (pq PriorityQueue) Len() int {
	return len(pq)
}
func BoolToInt(b bool) int {
	if b {
		return 1
	} else {
		return 0
	}
}
func (pq PriorityQueue) Less(i, j int) bool {
	//last must be not expireing secrets no matter time they expire
	if pq[i].doesExpire != pq[j].doesExpire {
		return BoolToInt(pq[i].doesExpire) > BoolToInt(pq[j].doesExpire)
	}
	if pq[i].ExpiresAt == pq[j].ExpiresAt {
		return pq[i].Hash < pq[j].Hash
	}
	return pq[i].ExpiresAt.Before(pq[j].ExpiresAt) //same as: pq[i].ExpiresAt < pq[j].ExpiresAt
}
func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}
func (pq *PriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*Secret)
	item.index = n
	*pq = append(*pq, item)
}
func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

type AllSecrets struct {
	mu    sync.Mutex
	mp    map[string]*Secret
	pq    PriorityQueue
	PqMux *sync.Mutex
}

func New() *AllSecrets {
	ts := &AllSecrets{}
	ts.mp = make(map[string]*Secret)

	ts.pq = make(PriorityQueue, 0)
	ts.PqMux = new(sync.Mutex)
	// establish the priority queue (heap) invariants.
	heap.Init(&ts.pq)
	return ts
}
