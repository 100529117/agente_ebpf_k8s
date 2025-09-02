package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	ebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	rb "github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	kyv "tfm.com/perpod-ebpf/internal/kyverno"
)

// Manejador para el eBPF de reverse shell
var rs *rsSensor

const (
	labelKey   = "agente.monitoreo/habilitado"
	labelValue = "true"

	hostProc = "/host/proc"
)

const (
	defaultRootDir = "/var/run/perpod-ebpf"
)

var contIDRe = regexp.MustCompile(`^(?:containerd|cri-o|docker)://([a-f0-9]{12,64})$`)

// Objetos para el monitor de pruebas exec

type execObjects struct {
	Watchlist *ebpf.Map
	Events    *ebpf.Map
	Link      link.Link
}

// Objetos para el monitor de ataques privilege-escalation (PE)

type peObjects struct {
	Watchlist *ebpf.Map // watchlist_priv
	Alerts    *ebpf.Map // ringbuf
	Links     []link.Link
}

// Metadatos de los Pod 

type podMeta struct{ Namespace, Pod string }

var (
	metaMu  sync.RWMutex
	metas   = map[uint32]podMeta{} // mntns -> meta

	scoreMu   sync.Mutex
	scores    = map[uint32]int{} // mntns -> puntaje/score
	lastEvent = map[uint32]time.Time{}
)

var (
	debounce    = 3 * time.Second
	cooldown    = 10 * time.Second
	lastCode    = map[uint32]map[uint32]time.Time{} // mntns -> codigo -> ultima vez
	coolingTill = map[uint32]time.Time{}            // mntns -> hasta
)

var (
	gKM   *kyv.Manager         // Gestor para Kyverno (inicializados en el metodo main())
	gKube kubernetes.Interface // Cliente tipado para K8s (para recuperar los pods)
)

func setMeta(m uint32, ns, pod string) { metaMu.Lock(); metas[m] = podMeta{ns, pod}; metaMu.Unlock() }
func delMeta(m uint32)                 { metaMu.Lock(); delete(metas, m); metaMu.Unlock() }
func lookupMeta(m uint32) podMeta      { metaMu.RLock(); defer metaMu.RUnlock(); return metas[m] }

// ---- Loaders ----

func loadExecBpf() (*execObjects, error) {
	spec, err := ebpf.LoadCollectionSpec("/opt/agent/monitor.bpf.o")
	if err != nil {
		return nil, fmt.Errorf("Error al cargar eBPF Monitor Exec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("Error en leer coleccion: %w", err)
	}
	objs := &execObjects{
		Watchlist: coll.Maps["watchlist"],
		Events:    coll.Maps["events"],
	}
	prog := coll.Programs["on_execve"]
	if prog == nil {
		return nil, fmt.Errorf("Gancho on_execve no encontrado")
	}
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		return nil, fmt.Errorf("Error al enganchar sys_enter_execve: %w", err)
	}
	objs.Link = tp
	return objs, nil
}

func loadPeBpf() (*peObjects, error) {
	spec, err := ebpf.LoadCollectionSpec("/opt/agent/privilege_escalation.bpf.o")
	if err != nil {
		return nil, fmt.Errorf("Error al cargar eBPF: %w", err)
	}
 
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("Error en leer coleccion: %w", err)
	}
	obj := &peObjects{
		Watchlist: coll.Maps["watchlist_priv"],
		Alerts:    coll.Maps["alerts"],
	}

	// Enganche de los tracepoints para PE
	attach := func(name, cat, evt string) {
		if prog := coll.Programs[name]; prog != nil {
			if l, err := link.Tracepoint(cat, evt, prog, nil); err == nil {
				obj.Links = append(obj.Links, l)
			} else {
				log.Printf("[warn] enganchando %s/%s: %v", cat, evt, err)
			}
		}
	}
	attach("pe_unshare", "syscalls", "sys_enter_unshare")
	attach("pe_setns", "syscalls", "sys_enter_setns")
	attach("pe_clone", "syscalls", "sys_enter_clone")
	attach("pe_clone3", "syscalls", "sys_enter_clone3")
	attach("pe_capset", "syscalls", "sys_enter_capset")
	attach("pe_ptrace", "syscalls", "sys_enter_ptrace")
	attach("pe_mount", "syscalls", "sys_enter_mount")
	attach("pe_pivot", "syscalls", "sys_enter_pivot_root")
	attach("pe_bpf", "syscalls", "sys_enter_bpf")
	attach("pe_setresuid", "syscalls", "sys_enter_setresuid")
	attach("pe_setuid", "syscalls", "sys_enter_setuid")
 
  log.Printf("[agent] sensor escala privilegios cargado.")
	return obj, nil
}

func getenv(k, d string) string { v := os.Getenv(k); if v == "" { return d }; return v }

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("[agent] Iniciando...")

	root := getenv("PERPOD_ROOT", defaultRootDir)
	logDir := filepath.Join(root, "logs")
	_ = os.MkdirAll(logDir, 0o755)

	ts := time.Now().UTC().Format("20060102T150405Z")
	lf, err := os.OpenFile(filepath.Join(logDir, "agent-"+ts+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		log.Printf("[warn] cargando archivo log:: %v", err)
	} else {
		log.SetOutput(io.MultiWriter(os.Stdout, lf)) // escribamos en pantalla y archivo
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[warn] Error al tratar de aumentar valor RLIMIT_MEMLOCK: %v", err)
	}

	execObjs, err := loadExecBpf()
	if err != nil {
		log.Fatalf("Error al cargar eBPF: %v", err)
	}
	defer execObjs.Link.Close()
	defer execObjs.Watchlist.Close()
	defer execObjs.Events.Close()

	peObjs, err := loadPeBpf()
	if err != nil {
		log.Fatalf("Error al cargar eBPF: %v", err)
	}
	defer func() { for _, l := range peObjs.Links { _ = l.Close() } }()
	defer peObjs.Watchlist.Close()
	defer peObjs.Alerts.Close()

	if s, err := startReverseShellSensor("/opt/agent/reverse_shell_detector.bpf.o"); err != nil {
		log.Printf("[warn] sensor de reverse-shell: %v", err)
	} else {
		rs = s
		defer rs.Close()
		go readReverseShellRing(context.Background(), rs)
	}

	// Iniciar lectores
	go readExecRing(execObjs.Events)
	go readPeRing(peObjs.Alerts)

	// Iniciar cliente K8s
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Error en k8s: %v", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("Error en cliente k8s: %v", err)
	}

	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("Error en cliente k8s: %v", err)
	}
	gKube = cs

	policyDir := filepath.Join(root, "policies", "generated")
	gKM = kyv.NewWithStorage(cs, dyn, policyDir, logDir)

	if err := gKM.Ensure(context.Background()); err != nil {
		log.Printf("[warn] Lista de baneo en Kyverno: %v", err)
	}

	factory := informers.NewSharedInformerFactoryWithOptions(cs, 0,
		informers.WithTweakListOptions(func(lo *metav1.ListOptions) {
			lo.LabelSelector = fmt.Sprintf("%s=%s", labelKey, labelValue)
			lo.FieldSelector = fields.Everything().String()
		}),
	)

	podInf := factory.Core().V1().Pods().Informer()

	watchlists := []*ebpf.Map{execObjs.Watchlist, peObjs.Watchlist}
	if rs != nil && rs.wlMap != nil {
		watchlists = append(watchlists, rs.wlMap)
	}
	rh := &resourceHandler{cs: cs, watchlists: watchlists}

	podInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if p := asPod(obj); p != nil {
				rh.sync(p)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if p := asPod(newObj); p != nil {
				rh.sync(p)
			}
		},
		DeleteFunc: func(obj interface{}) {
			if p := asPod(obj); p != nil {
				rh.removePod(p)
			}
		},
	})

	stop := make(chan struct{})
	factory.Start(stop)
	factory.WaitForCacheSync(stop)

	log.Println("[agent] ejecutandose. Observando solo pods etiquetados.")
	<-stop
}


func readExecRing(events *ebpf.Map) {
	reader, err := rb.NewReader(events)
	if err != nil {
		log.Fatalf("Error en Ringbuf (exec): %v", err)
	}
	defer reader.Close()

	for {
		rec, err := reader.Read()
		if err != nil {
			if errors.Is(err, rb.ErrClosed) || errors.Is(err, syscall.EINTR) {
				return
			}
			continue
		}
		if len(rec.RawSample) < 8+4+4+4+4+16+256 {
			continue
		}
    //Descomentar en caso de depuracion.
		/*b := rec.RawSample
		ts := le64(b[0:8])
		pid := le32(b[8:12])
		tgid := le32(b[12:16])
		uid := le32(b[16:20])
		mntns := le32(b[20:24])
		comm := cstr(b[24:40])
		filename := cstr(b[40:296])
		meta := lookupMeta(mntns)
		log.Printf("[exec] ts=%d ns=%s pod=%s mntns=%d pid=%d tgid=%d uid=%d comm=%s filename=%s",
			ts, meta.Namespace, meta.Pod, mntns, pid, tgid, uid, comm, filename) */
	}
}

// scoring

type alert struct {
	ts    uint64
	pid   uint32
	tgid  uint32
	uid   uint32
	mntns uint32
	code  uint32
	arg   uint64
	comm  string
}

const (
	aUnshareUser = 1
	aSetnsUser   = 2
	aCloneUser   = 3
	aClone3User  = 4
	aCapset      = 5
	aPtrace      = 6
	aMount       = 7
	aPivotRoot   = 8
	aBPF         = 9
	aSetUID0     = 10
)

var (
	weights = map[uint32]int{
		aUnshareUser: 7,
		aSetnsUser:   6,
		aCloneUser:   6,
		aClone3User:  0,
		aCapset:      4,
		aPtrace:      7,
		aMount:       5,
		aPivotRoot:   8,
		aBPF:         4,
		aSetUID0:     8,
	}
	threshold = 12
	decay     = 30 * time.Second
)

func readPeRing(alerts *ebpf.Map) {
	reader, err := rb.NewReader(alerts)
	if err != nil {
		log.Fatalf("Error en ringbuf (alertas): %v", err)
	}
	defer reader.Close()

	for {
		rec, err := reader.Read()
		if err != nil {
			if errors.Is(err, rb.ErrClosed) || errors.Is(err, syscall.EINTR) {
				return
			}
			continue
		}

		if len(rec.RawSample) < 8+4+4+4+4+4+8+16 {
			continue
		}
		b := rec.RawSample
		a := alert{}
		a.ts = le64(b[0:8])
		a.pid = le32(b[8:12])
		a.tgid = le32(b[12:16])
		a.uid = le32(b[16:20])
		a.mntns = le32(b[20:24])
		a.code = le32(b[24:28])
		a.arg = binary.LittleEndian.Uint64(b[28:36])
		a.comm = cstr(b[36:52])

		meta := lookupMeta(a.mntns)

		if a.code == aCapset {
			if c := strings.ToLower(a.comm); c == "apt" || c == "apt-get" || c == "dpkg" || c == "gpgv" {
				continue
			}
		}

		// decadencia al puntaje
		w := weights[a.code]
		if a.code == aBPF {
			if a.arg == 5 {
				w += 6 
			}
		}
		scoreMu.Lock()
		now := time.Now()

		if until, ok := coolingTill[a.mntns]; ok && now.Before(until) {
			scoreMu.Unlock()
			continue // si se encuentra todavia en ventana de enfriamiento
		}
		if lastCode[a.mntns] == nil {
			lastCode[a.mntns] = map[uint32]time.Time{}
		}
		if t, ok := lastCode[a.mntns][a.code]; ok && now.Sub(t) < debounce {
			scoreMu.Unlock()
			continue // ignorar repeticiones rapidas del mismo codigo
		}
		lastCode[a.mntns][a.code] = now

		if t, ok := lastEvent[a.mntns]; ok && now.Sub(t) > decay {
			scores[a.mntns] = 0
		}
		lastEvent[a.mntns] = now
		scores[a.mntns] += w
		sc := scores[a.mntns]
		scoreMu.Unlock()

		log.Printf("[pe] ns=%s pod=%s mntns=%d pid=%d code=%d(+%d) score=%d",
			meta.Namespace, meta.Pod, a.mntns, a.pid, a.code, weights[a.code], sc)

		if sc >= threshold {
			log.Printf("[ALERT] POSIBLE PRIV-ESC: ns=%s pod=%s mntns=%d score=%d (trigger=%d)",
				meta.Namespace, meta.Pod, a.mntns, sc, a.code)

			// Iniciar la respuesta del incidente con Kyverno de forma asíncrona 
			ns, pod := meta.Namespace, meta.Pod
			go func(ns, pod string) {
				if err := handleIncident(context.Background(), ns, pod); err != nil {
					log.Printf("[warn] incidente->kyverno ns=%s pod=%s: %v", ns, pod, err)
				}
			}(ns, pod)

			scoreMu.Lock()
			scores[a.mntns] = 0
			coolingTill[a.mntns] = time.Now().Add(cooldown)
			scoreMu.Unlock()
		}
	}
}

// Actualiza la lista de baneo y crea una politica de limpieza para el pod.
func handleIncident(ctx context.Context, ns, pod string) error {
	if gKM == nil || gKube == nil {
		return fmt.Errorf("Gestor de Kyverno no iniciado...")
	}

	// capturar huella digital (image + serviceAccount)
	p, err := gKube.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Error al obtener pod: %w", err)
	}
	imgs := imagesFromPod(p)
	fp := kyv.Fingerprint{
		Namespace:      ns,
		PodName:        pod,
		Images:         imgs,
		ServiceAccount: p.Spec.ServiceAccountName,
	}

	// 1) se agrega a la lista de baneos para futuros pods
	if err := gKM.UpdateBanlist(ctx, fp); err != nil {
		return fmt.Errorf("Lista de baneos actualizado: %w", err)
	}

	// 2) se crea la poltica en el ambito del namespace
	if err := gKM.CreatePreventionPolicy(ctx, fp); err != nil {
		return fmt.Errorf("Generando politica preventiva: %w", err)
	}

	// 3) se crea politica de limpieza del pod en el ambito del namespace
	if err := gKM.CreateCleanupForPod(ctx, ns, pod); err != nil {
		return fmt.Errorf("Generando politica de limpieza y ciere para pod: %w", err)
	}

	log.Printf("[kyverno] lista de baneados actualizado (imgs=%d, sa=%q); terminacion de pod establecido en %s/%s",
		len(imgs), p.Spec.ServiceAccountName, ns, pod)
	return nil
}

// recopilamos las imagenes de los contenedores
func imagesFromPod(p *corev1.Pod) []string {
	if p == nil {
		return nil
	}
	uniq := map[string]struct{}{}
	add := func(img string) {
		if img == "" {
			return
		}
		if _, ok := uniq[img]; !ok {
			uniq[img] = struct{}{}
		}
	}
	for _, c := range p.Spec.InitContainers {
		add(c.Image)
	}
	for _, c := range p.Spec.Containers {
		add(c.Image)
	}
	out := make([]string, 0, len(uniq))
	for k := range uniq {
		out = append(out, k)
	}
	return out
}


type resourceHandler struct {
	cs         *kubernetes.Clientset
	watchlists []*ebpf.Map // exec + pe + rs watchlists
}

func (h *resourceHandler) sync(pod *corev1.Pod) {
	if pod == nil {
		return
	}
	if pod.Status.Phase == corev1.PodPending || pod.Status.Phase == corev1.PodUnknown {
		go func(ns, name string) {
			time.Sleep(2 * time.Second)
			p, err := h.cs.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
			if err == nil {
				h.sync(p)
			}
		}(pod.Namespace, pod.Name)
		return
	}

	ids := map[uint32]struct{}{}
	for _, st := range allStatuses(pod) {
		pid, err := containerInitPID(&st)
		if err != nil {
			continue
		}
		if m, err := mountNSInum(pid); err == nil {
			ids[m] = struct{}{}
		}
	}

	for m := range ids {
		setMeta(m, pod.Namespace, pod.Name)
		for _, wl := range h.watchlists {
			var existing uint8
			if err := wl.Lookup(&m, &existing); err == nil {
				continue
			}
			one := uint8(1)
			if err := wl.Update(&m, &one, ebpf.UpdateAny); err != nil {
				log.Printf("[error] al monitorear mntns=%d para %s/%s: %v", m, pod.Namespace, pod.Name, err)
			} else {
				log.Printf("[watch] %s/%s mntns=%d agregado.", pod.Namespace, pod.Name, m)
			}
		}
	}
}

func (h *resourceHandler) removePod(pod *corev1.Pod) {
	if pod == nil {
		return
	}
	for _, st := range allStatuses(pod) {
		pid, err := containerInitPID(&st)
		if err != nil {
			continue
		}
		m, err := mountNSInum(pid)
		if err != nil {
			continue
		}
		for _, wl := range h.watchlists {
			_ = wl.Delete(&m)
		}
		delMeta(m)
		log.Printf("[unwatch] %s/%s mntns=%d removido.", pod.Namespace, pod.Name, m)
	}
}

func allStatuses(p *corev1.Pod) []corev1.ContainerStatus {
	if p == nil {
		return nil
	}
	out := make([]corev1.ContainerStatus, 0, len(p.Status.InitContainerStatuses)+len(p.Status.ContainerStatuses)+len(p.Status.EphemeralContainerStatuses))
	out = append(out, p.Status.InitContainerStatuses...)
	out = append(out, p.Status.ContainerStatuses...)
	out = append(out, p.Status.EphemeralContainerStatuses...)
	return out
}

func asPod(obj interface{}) *corev1.Pod {
	switch t := obj.(type) {
	case *corev1.Pod:
		return t
	case cache.DeletedFinalStateUnknown:
		if p, ok := t.Obj.(*corev1.Pod); ok {
			return p
		}
		return nil
	default:
		return nil
	}
}

// auxiliares para parsear
func le32(b []byte) uint32 { return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24 }
func le64(b []byte) uint64 { return uint64(le32(b[0:4])) | uint64(le32(b[4:8]))<<32 }

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}


func containerIDFromStatus(st *corev1.ContainerStatus) string {
	if st == nil || st.ContainerID == "" {
		return ""
	}
	m := contIDRe.FindStringSubmatch(st.ContainerID)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

// containerInitPID resuelve el PID de inicio de un contenedor utilizando alternativas
// 1) containerd init.pid
// 2) containerd state.json (campo Pid)
// 3) escanear /host/proc/*/cgroup en busca del ID del contenedor
// 4) escanear cgroupfs en busca de un ámbito coincidente y leer cgroup.procs
func containerInitPID(st *corev1.ContainerStatus) (int, error) {
	if st.ContainerID == "" {
		return 0, fmt.Errorf("no containerID yet")
	}
	cid := containerIDFromStatus(st)
	if cid == "" {
		return 0, fmt.Errorf("unexpected containerID: %s", st.ContainerID)
	}

	// 1) init.pid
	path := filepath.Join("/run/containerd/io.containerd.runtime.v2.task/k8s.io", cid, "init.pid")
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		if sc.Scan() {
			var pid int
			if _, e := fmt.Sscanf(strings.TrimSpace(sc.Text()), "%d", &pid); e == nil && pid > 0 {
				return pid, nil
			}
		}
	}

	// 2) state.json
	if pid, err := containerdStatePid(cid); err == nil && pid > 0 {
		return pid, nil
	}

	// 3) /host/proc
	if pid, err := findPidByCID(cid); err == nil {
		return pid, nil
	}

	// 4) cgroupfs 
	if pid, err := findPidByCIDViaCgroupFS(cid); err == nil {
		return pid, nil
	}

	return 0, fmt.Errorf("no se encontro pid para cid %s", cid)
}

func containerdStatePid(cid string) (int, error) {
	p := filepath.Join("/run/containerd/io.containerd.runtime.v2.task/k8s.io", cid, "state.json")
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return 0, err
	}

	if v, ok := m["Pid"]; ok {
		switch t := v.(type) {
		case float64:
			if int(t) > 0 {
				return int(t), nil
			}
		case int:
			if t > 0 {
				return t, nil
			}
		}
	}
	if v, ok := m["pid"]; ok {
		switch t := v.(type) {
		case float64:
			if int(t) > 0 {
				return int(t), nil
			}
		case int:
			if t > 0 {
				return t, nil
			}
		}
	}
	return 0, fmt.Errorf("no se encontro pid en archivo state.json")
}

func findPidByCID(cid string) (int, error) {
	short := cid
	if len(short) > 12 {
		short = cid[:12]
	}

	d, err := os.ReadDir(hostProc)
	if err != nil {
		return 0, err
	}
	for _, de := range d {
		if !de.IsDir() {
			continue
		}
		name := de.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		pid, err := strconv.Atoi(name)
		if err != nil || pid <= 0 {
			continue
		}
		cg, err := os.ReadFile(filepath.Join(hostProc, name, "cgroup"))
		if err != nil {
			continue
		}
		s := string(cg)
		if strings.Contains(s, cid) || strings.Contains(s, short) {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("no se encontro pid para cid %s", cid)
}

func findPidByCIDViaCgroupFS(cid string) (int, error) {
	short := cid
	if len(short) > 12 {
		short = cid[:12]
	}

	candidates := []string{
		"/sys/fs/cgroup/system.slice/cri-containerd-" + cid + ".scope/cgroup.procs",
		"/sys/fs/cgroup/system.slice/docker-" + cid + ".scope/cgroup.procs",
		"/sys/fs/cgroup/crio-" + cid + "/cgroup.procs",
	}
	for _, p := range candidates {
		if b, err := os.ReadFile(p); err == nil {
			lines := strings.Split(string(b), "\n")
			for _, ln := range lines {
				ln = strings.TrimSpace(ln)
				if ln == "" {
					continue
				}
				if pid, err := strconv.Atoi(ln); err == nil && pid > 0 {
					return pid, nil
				}
			}
		}
	}

	// ciclo limitado a 50000
	max, count, found := 50000, 0, 0
	_ = filepath.WalkDir("/sys/fs/cgroup", func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if count > max || found > 0 {
			return filepath.SkipDir
		}
		count++
		if d.IsDir() && (strings.Contains(path, cid) || strings.Contains(path, short)) {
			procs := filepath.Join(path, "cgroup.procs")
			if b, e := os.ReadFile(procs); e == nil {
				lines := strings.Split(string(b), "\n")
				for _, ln := range lines {
					ln = strings.TrimSpace(ln)
					if ln == "" {
						continue
					}
					if pid, e2 := strconv.Atoi(ln); e2 == nil && pid > 0 {
						found = pid
						return filepath.SkipDir
					}
				}
			}
		}
		return nil
	})
	if found > 0 {
		return found, nil
	}
	return 0, fmt.Errorf("No se encontro pid en cgroupfs para cid %s", cid)
}

func mountNSInum(pid int) (uint32, error) {
	nsPath := filepath.Join(hostProc, fmt.Sprintf("%d/ns/mnt", pid))
	st := &syscall.Stat_t{}
	if err := syscall.Stat(nsPath, st); err != nil {
		return 0, err
	}
	return uint32(st.Ino), nil
}
