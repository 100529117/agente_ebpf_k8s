BPF_CLANG ?= clang
BPF_CFLAGS_BASE := -O2 -g -target bpf
SALIDA ?= build

ifeq ($(TARGETARCH),arm64)
  BPF_ARCH := -D__TARGET_ARCH_arm64
else ifeq ($(TARGETARCH),amd64)
  BPF_ARCH := -D__TARGET_ARCH_x86
else
  UNAME_M := $(shell uname -m)
  ifeq ($(UNAME_M),aarch64)
    BPF_ARCH := -D__TARGET_ARCH_arm64
  else
    BPF_ARCH := -D__TARGET_ARCH_x86
  endif
endif

BPF_CFLAGS := $(BPF_CFLAGS_BASE) $(BPF_ARCH)

.PHONY: all programas clean

all: programas

$(SALIDA):
	mkdir -p $(SALIDA)

# Generar el vmlinux.h del BTF del kernel
bpf/vmlinux.h:
	@if [ ! -r /sys/kernel/btf/vmlinux ]; then \
	  echo "ERROR: /sys/kernel/btf/vmlinux no encontrado en el sistema operativo." >&2; \
	  exit 1; \
	fi
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(SALIDA)/monitor.bpf.o: bpf/monitor.bpf.c bpf/vmlinux.h | $(SALIDA)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
 
$(SALIDA)/privilege_escalation.bpf.o: bpf/privilege_escalation.bpf.c bpf/vmlinux.h | $(SALIDA)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
 
 $(SALIDA)/reverse_shell_detector.bpf.o: bpf/reverse_shell_detector.bpf.c bpf/vmlinux.h | $(SALIDA)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SALIDA)/agente: | $(SALIDA)
	CGO_ENABLED=0 GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) go build -trimpath -ldflags='-s -w' -o $(SALIDA)/agent ./cmd/agent

programas: $(SALIDA)/monitor.bpf.o $(SALIDA)/privilege_escalation.bpf.o $(SALIDA)/reverse_shell_detector.bpf.o $(SALIDA)/agent

clean:
	rm -rf $(SALIDA) bpf/vmlinux.h
	rm -rf $(SALIDA) bpf/*.o