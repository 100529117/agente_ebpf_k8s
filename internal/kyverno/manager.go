package kyverno

import (
  "os"
  "context"
  "crypto/sha1"
  "encoding/hex"
  "encoding/json"
  "path/filepath"
  "fmt"
  "time"
  "sort"
  "log"
  "strings"

  corev1 "k8s.io/api/core/v1"
  netv1 "k8s.io/api/networking/v1"
  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
  "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
  "k8s.io/apimachinery/pkg/runtime/schema"
  "k8s.io/client-go/kubernetes"
  "k8s.io/client-go/dynamic"
  sigsyaml "sigs.k8s.io/yaml"
  "k8s.io/apimachinery/pkg/types"
)

var newPolicyTtl string = "24h"

type Manager struct {
  Kube    kubernetes.Interface
  Dynamic dynamic.Interface
  NS      string // namespace
  CMName  string // "perpod-ebpf-banlist"
  PolicyDir string // directorio para las politicas generadas
  LogDir    string // logs
}

func NewWithStorage(K kubernetes.Interface, D dynamic.Interface, policyDir, logDir string) *Manager {
  _ = os.MkdirAll(policyDir, 0o755)
  _ = os.MkdirAll(logDir, 0o755)
  return &Manager{
    Kube: K, Dynamic: D, NS: "security", CMName: "perpod-ebpf-banlist",
    PolicyDir: policyDir, LogDir: logDir,
  }
}

func tsUTC() string { return time.Now().UTC().Format("20060102T150405Z") }

func (m *Manager) writeYAML(kind, ns, name string, obj any) {
  b, err := sigsyaml.Marshal(obj)
  if err != nil { return }
  fn := fmt.Sprintf("%s-%s-%s-%s.yaml", strings.ToLower(kind), ns, name, tsUTC())
  _ = os.WriteFile(filepath.Join(m.PolicyDir, fn), b, 0o640)
}

func New(K kubernetes.Interface, D dynamic.Interface) *Manager {
  //return &Manager{Kube: K, Dynamic: D, NS: "security", CMName: "perpod-ebpf-banlist"}
  return NewWithStorage(K, D, "/var/run/perpod-ebpf/policies/generated", "/var/run/perpod-ebpf/logs")
}

func (m *Manager) Ensure(ctx context.Context) error {
  _, err := m.Kube.CoreV1().ConfigMaps(m.NS).Get(ctx, m.CMName, metav1.GetOptions{})
  if err == nil { return nil }

  cm := &corev1.ConfigMap{
    ObjectMeta: metav1.ObjectMeta{Name: m.CMName, Namespace: m.NS},
    Data: map[string]string{
      "images":           "[]",
      "serviceAccounts":  "[]",
      "dangerousCaps":    `["SYS_ADMIN","SYS_PTRACE","BPF"]`,
    },
  }
  _, err = m.Kube.CoreV1().ConfigMaps(m.NS).Create(ctx, cm, metav1.CreateOptions{})
  return err
}

func uniqueAppend(list []string, vals ...string) []string {
  seen := map[string]struct{}{}
  for _, v := range list { seen[v] = struct{}{} }
  for _, v := range vals {
    if v == "" { continue }
    if _, ok := seen[v]; !ok { list = append(list, v); seen[v] = struct{}{} }
  }
  return list
}

type Fingerprint struct {
  Namespace       string
  PodName         string
  Images          []string
  ServiceAccount  string
}

func (m *Manager) UpdateBanlist(ctx context.Context, fp Fingerprint) error {
  return retry(func() error {
    cm, err := m.Kube.CoreV1().ConfigMaps(m.NS).Get(ctx, m.CMName, metav1.GetOptions{})
    if err != nil { return err }

    var imgs, sas []string
    _ = json.Unmarshal([]byte(cm.Data["images"]), &imgs)
    _ = json.Unmarshal([]byte(cm.Data["serviceAccounts"]), &sas)

    imgs = uniqueAppend(imgs, fp.Images...)
    sas  = uniqueAppend(sas, fp.ServiceAccount)

    ib, _ := json.Marshal(imgs)
    sb, _ := json.Marshal(sas)
    if cm.Data == nil { cm.Data = map[string]string{} }
    cm.Data["images"] = string(ib)
    cm.Data["serviceAccounts"] = string(sb)

    _, err = m.Kube.CoreV1().ConfigMaps(m.NS).Update(ctx, cm, metav1.UpdateOptions{})
    
    snap := map[string]any{
      "apiVersion":"v1","kind":"ConfigMap",
      "metadata": map[string]any{"name": m.CMName, "namespace": m.NS},
      "data": cm.Data,
    }
    b, _ := sigsyaml.Marshal(snap)
    _ = os.WriteFile(filepath.Join(m.LogDir, "banlist-"+tsUTC()+".yaml"), b, 0o640)
    
    return err
  })
}

func (m *Manager) CreateCleanupForPod(ctx context.Context, ns, pod string) error {
  gvr := schema.GroupVersionResource{Group: "kyverno.io", Version: "v2", Resource: "cleanuppolicies"}
  obj := &unstructured.Unstructured{
    Object: map[string]interface{}{
      "apiVersion": "kyverno.io/v2",
      "kind":       "CleanupPolicy",
      "metadata": map[string]interface{}{
        "name":      fmt.Sprintf("cleanup-%s", pod),
        "namespace": ns,
        "labels": map[string]interface{}{
          "app.kubernetes.io/part-of": "perpod-ebpf",
        },
      },
      "spec": map[string]interface{}{
        "match": map[string]interface{}{
          "any": []interface{}{
            map[string]interface{}{
              "resources": map[string]interface{}{
                "kinds": []interface{}{"Pod"},
                "names": []interface{}{pod},
              },
            },
          },
        },
        "schedule": "*/1 * * * *",
        "deletionPropagationPolicy": "Foreground",
      },
    },
  }

  m.writeYAML("CleanupPolicy", ns, pod, obj.Object)
  log.Printf("[kyverno] politica de limpieza creada: %s/%s (Pod objetivo=%s)", ns, fmt.Sprintf("cleanup-%s", pod), pod)

  _, err := m.Dynamic.Resource(gvr).Namespace(ns).Get(ctx, obj.GetName(), metav1.GetOptions{})
  if err == nil {
    _, err = m.Dynamic.Resource(gvr).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{})
    return err
  }
  _, err = m.Dynamic.Resource(gvr).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
  return err
}

func retry(fn func() error) error {
  var last error
  for i := 0; i < 6; i++ {
    if err := fn(); err != nil {
      last = err
      time.Sleep(150 * time.Millisecond)
      continue
    }
    return nil
  }
  return last
}

func policyNameFrom(fp Fingerprint) string {
    imgs := append([]string{}, fp.Images...)
    sort.Strings(imgs)
    sum := sha1.Sum([]byte(fp.Namespace + "|" + fp.ServiceAccount + "|" + strings.Join(imgs, ",")))
    return "deny-incident-" + hex.EncodeToString(sum[:])[:16]
}

// Crear o actualizar una política de Kyverno con espacio de nombres que rechace pods por imagen o cuenta de servicio.
func (m *Manager) CreatePreventionPolicy(ctx context.Context, fp Fingerprint) error {
    gvr := schema.GroupVersionResource{Group: "kyverno.io", Version: "v1", Resource: "policies"}
    name := policyNameFrom(fp)

    // Condiciones denegacion (deny):
    // - AnyIn(containers[].image) en imagen
    // - AnyIn(initContainers[].image) en imagen
    // - Equals(serviceAccountName) == fp.ServiceAccount
    imagesAnyIn := func(key string) map[string]interface{} {
        vals := make([]interface{}, 0, len(fp.Images))
        for _, v := range fp.Images { if v != "" { vals = append(vals, v) } }
        return map[string]interface{}{
            "key":      key,
            "operator": "AnyIn",
            "value":    vals,
        }
    }
    saEquals := map[string]interface{}{
        "key":      "{{ request.object.spec.serviceAccountName }}",
        "operator": "Equals",
        "value":    fp.ServiceAccount,
    }

    obj := &unstructured.Unstructured{
        Object: map[string]interface{}{
            "apiVersion": "kyverno.io/v1",
            "kind":       "Policy", // dirigido a un namespace especifico
            "metadata": map[string]interface{}{
                "name":      name,
                "namespace": fp.Namespace,
                "labels": map[string]interface{}{
                    "app.kubernetes.io/part-of": "perpod-ebpf",
                    "perpod-ebpf/fingerprint":   "true",
                },
                "annotations": map[string]interface{}{
                    "perpod-ebpf/incident-pod": fmt.Sprintf("%s/%s", fp.Namespace, fp.PodName),
                    "cleanup.kyverno.io/ttl": newPolicyTtl,
                },
            },
            "spec": map[string]interface{}{
                "validationFailureAction": "Enforce",
                "background":              true,
                "rules": []interface{}{
                    map[string]interface{}{
                        "name": "block-by-fingerprint",
                        "match": map[string]interface{}{
                            "any": []interface{}{
                                map[string]interface{}{
                                    "resources": map[string]interface{}{
                                        "kinds":      []interface{}{"Pod"},
                                        "operations": []interface{}{"CREATE", "UPDATE"},
                                    },
                                },
                            },
                        },
                        "validate": map[string]interface{}{
                            "message": "Pod blocked: matches runtime incident fingerprint (image or serviceAccount).",
                            "deny": map[string]interface{}{
                                "conditions": map[string]interface{}{
                                    "any": []interface{}{
                                        imagesAnyIn("{{ request.object.spec.containers[].image || [] }}"),
                                        imagesAnyIn("{{ request.object.spec.initContainers[].image || [] }}"),
                                        saEquals,
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }

    
    m.writeYAML("Policy", fp.Namespace, name, obj.Object)
    r := m.Dynamic.Resource(gvr).Namespace(fp.Namespace)
    log.Printf("[kyverno] politica de prevencion generada: ns=%s name=%s (images=%d sa=%q)",
    fp.Namespace, name, len(fp.Images), fp.ServiceAccount)
    if _, err := r.Get(ctx, name, metav1.GetOptions{}); err == nil {
        _, err = r.Update(ctx, obj, metav1.UpdateOptions{})
        return err
    }
    _, err := r.Create(ctx, obj, metav1.CreateOptions{})
    return err
}

func (m *Manager) TempQuarantineEgress(ctx context.Context, ns, pod string, duration time.Duration) error {
	if m.Kube == nil {
		return fmt.Errorf("Ciente k8s no iniciado.")
	}
	if duration <= 0 {
		duration = 15 * time.Minute
	}

	// 1) añadir una etiqueta de cuarentena unica
	qKey := "perpod-ebpf/quarantined"
	qVal := time.Now().UTC().Format("20060102t150405z")
	patch := fmt.Sprintf(`{"metadata":{"labels":{"%s":"%s"}}}`, qKey, qVal)
	if _, err := m.Kube.CoreV1().Pods(ns).Patch(ctx, pod, types.MergePatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("en label de pod en cuarentena: %w", err)
	}

	// 2) crea una politica de red para denegar todo el trafico de salida para el pod etiquetado
	npName := fmt.Sprintf("perpod-ebpf-quarantine-%s", qVal)
	np := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      npName,
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/part-of": "perpod-ebpf",
				"perpod-ebpf/quarantine":    "true",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{qKey: qVal},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
			Egress: []netv1.NetworkPolicyEgressRule{},
		},
	}

	if _, err := m.Kube.NetworkingV1().NetworkPolicies(ns).Create(ctx, np, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("Error al crear NetworkPolicy para aislar pod temporalmente: %w", err)
	}
  log.Printf("[net] cuarentena en trafico de salida aplicado a %s/%s (%s)", ns, pod, duration)
	// 3) programar la eliminacion del pod
	go func(ns, pod, npName, qKey, qVal string, dur time.Duration) {
		timer := time.NewTimer(dur)
		defer timer.Stop()
		<-timer.C

		_ = m.Kube.NetworkingV1().NetworkPolicies(ns).Delete(context.Background(), npName, metav1.DeleteOptions{})

		remove := fmt.Sprintf(`{"metadata":{"labels":{"%s":null}}}`, qKey)
		_, _ = m.Kube.CoreV1().Pods(ns).Patch(context.Background(), pod, types.MergePatchType, []byte(remove), metav1.PatchOptions{})
	}(ns, pod, npName, qKey, qVal, duration)

	return nil
}
