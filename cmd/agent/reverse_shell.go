package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	ebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	rb "github.com/cilium/ebpf/ringbuf"
)

var quarantineMins int = 15

type rsEvent struct {
	Ts    uint64
	Pid   uint32
	Tgid  uint32
	Uid   uint32
	Mntns uint32
	Code  uint32
	Arg   uint32
	IPv4  uint32
	Comm  [16]byte
	Exe   [64]byte
}

const (
	rsConnectExternal = 1
	rsDupStdFD        = 2
	rsExecSuspect     = 3
)

var (
	rsWeights = map[uint32]int{
		rsConnectExternal: 5, // conexiones externas
		rsDupStdFD:        8, // dup hacia stdin/out/err
		rsExecSuspect:     4, // exec sh/nc/...
	}
	rsThreshold  = 12
	rsDecayEvery = 20 * time.Second
	rsCooldown   = 15 * time.Second
	rsDebounce   = 2 * time.Second

	rsScores   = map[uint32]int{}                  
	rsLastTime = map[uint32]time.Time{}            
	rsLastCode = map[uint32]map[uint32]time.Time{} 
	rsCooling  = map[uint32]time.Time{} 
)

type rsSensor struct {
	coll  *ebpf.Collection
	links []link.Link
	ring  *rb.Reader
	wlMap *ebpf.Map 
}

func (s *rsSensor) Close() {
	if s == nil {
		return
	}
	if s.ring != nil {
		_ = s.ring.Close()
	}
	for _, l := range s.links {
		_ = l.Close()
	}
	if s.coll != nil {
		s.coll.Close()
	}
}

func startReverseShellSensor(objPath string) (*rsSensor, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("Error al cargar eBPF: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("Error en leer coleccion: %w", err)
	}

	links := []link.Link{}
	attach := func(cat, evt, prog string) error {
		p := coll.Programs[prog]
		if p == nil {
			return fmt.Errorf("sensor %s no encontrado", prog)
		}
		l, err := link.Tracepoint(cat, evt, p, nil)
		if err != nil {
			return fmt.Errorf("error al engancho %s/%s: %w", cat, evt, err)
		}
		links = append(links, l)
		return nil
	}

	if err := attach("syscalls", "sys_enter_connect", "rs_enter_connect"); err != nil {
		coll.Close()
		return nil, err
	}
	if err := attach("syscalls", "sys_exit_connect", "rs_exit_connect"); err != nil {
		coll.Close()
		return nil, err
	}
	if err := attach("syscalls", "sys_enter_dup2", "rs_dup2"); err != nil {
		coll.Close()
		return nil, err
	}
	if err := attach("syscalls", "sys_enter_dup3", "rs_dup3"); err != nil {
		coll.Close()
		return nil, err
	}
	if err := attach("syscalls", "sys_enter_execve", "rs_execve"); err != nil {
		coll.Close()
		return nil, err
	}

	ring, err := rb.NewReader(coll.Maps["rs_events"])
	if err != nil {
		for _, l := range links {
			_ = l.Close()
		}
		coll.Close()
		return nil, fmt.Errorf("Error en Ringbuf: %w", err)
	}

	log.Printf("[agent] sensor reverse-shell cargado.")
	return &rsSensor{
		coll:  coll,
		links: links,
		ring:  ring,
		wlMap: coll.Maps["watchlist"],
	}, nil
}

func (s *rsSensor) addWatch(mntns uint32) error {
	if s == nil || s.wlMap == nil {
		return nil
	}
	var one uint8 = 1
	return s.wlMap.Update(&mntns, &one, ebpf.UpdateAny)
}

func readReverseShellRing(ctx context.Context, s *rsSensor) {
	defer s.Close()
	if s == nil || s.ring == nil {
		return
	}

	decayTicker := time.NewTicker(rsDecayEvery)
	defer decayTicker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-decayTicker.C:
				now := time.Now()
				for m, t := range rsLastTime {
					if now.Sub(t) > rsDecayEvery && rsScores[m] > 0 {
						rsScores[m] -= 2
						if rsScores[m] < 0 {
							rsScores[m] = 0
						}
					}
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rec, err := s.ring.Read()
		if err != nil {
			continue
		}

		var ev rsEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}

		now := time.Now()
		rsLastTime[ev.Mntns] = now
		if rsLastCode[ev.Mntns] == nil {
			rsLastCode[ev.Mntns] = map[uint32]time.Time{}
		}
		if t, ok := rsLastCode[ev.Mntns][ev.Code]; ok && now.Sub(t) < rsDebounce {
			continue
		}
		rsLastCode[ev.Mntns][ev.Code] = now

		if until, ok := rsCooling[ev.Mntns]; ok && now.Before(until) {
			continue
		}

		w := rsWeights[ev.Code]
		rsScores[ev.Mntns] += w
		score := rsScores[ev.Mntns]

		meta := lookupMeta(ev.Mntns)
		comm := string(bytes.TrimRight(ev.Comm[:], "\x00"))

		switch ev.Code {
		case rsConnectExternal:
			ip := fmt.Sprintf("%d.%d.%d.%d",
				(ev.IPv4>>24)&0xff, (ev.IPv4>>16)&0xff, (ev.IPv4>>8)&0xff, ev.IPv4&0xff)
			log.Printf("[rs] ns=%s pod=%s mntns=%d pid=%d conexion externa dst=%s:%d (+%d) score=%d",
				meta.Namespace, meta.Pod, ev.Mntns, ev.Pid, ip, ev.Arg, w, score)
		case rsDupStdFD:
			log.Printf("[rs] ns=%s pod=%s mntns=%d pid=%d dup stdfd=%d (+%d) score=%d",
				meta.Namespace, meta.Pod, ev.Mntns, ev.Pid, ev.Arg, w, score)
		case rsExecSuspect:
			exe := string(bytes.TrimRight(ev.Exe[:], "\x00"))
			log.Printf("[rs] ns=%s pod=%s mntns=%d pid=%d comm=%s exec=%s (+%d) score=%d",
				meta.Namespace, meta.Pod, ev.Mntns, ev.Pid, comm, exe, w, score)
		default:
			log.Printf("[rs] ns=%s pod=%s mntns=%d pid=%d code=%d (+%d) score=%d",
				meta.Namespace, meta.Pod, ev.Mntns, ev.Pid, ev.Code, w, score)
		}

		if score >= rsThreshold {
			log.Printf("[ALERT] POSIBLE REVERSE SHELL: ns=%s pod=%s mntns=%d score=%d (trigger=%d)",
				meta.Namespace, meta.Pod, ev.Mntns, score, ev.Code)

			rsScores[ev.Mntns] = 0
			rsCooling[ev.Mntns] = now.Add(rsCooldown)
      
      go func(ns, pod string) {
          if gKM != nil {
              if err := gKM.TempQuarantineEgress(context.Background(), ns, pod, time.Duration(quarantineMins)*time.Minute); err != nil {
                  log.Printf("[warn] rs en cuarentena via netpol ns=%s pod=%s: %v", ns, pod, err)
              } else {
                  log.Printf("[net] cuarentena para trafico de salida aplicado a %s/%s (15m)", ns, pod)
              }
          }
      }(meta.Namespace, meta.Pod)

			go func(ns, pod string) {
				if err := handleIncident(context.Background(), ns, pod); err != nil {
					log.Printf("[warn] rs incidente->kyverno ns=%s pod=%s: %v", ns, pod, err)
				}
			}(meta.Namespace, meta.Pod)
		}
	}
}
