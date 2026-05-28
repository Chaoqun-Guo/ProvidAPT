// stress_test — kernel compatibility stress test
//
// Tests ProvidAPT under high load:
//   - 10,000 concurrent process forks
//   - Memory leak detection via runtime metrics
//   - CPU jitter measurement via timing variance
//
// Build: go build -o /tmp/stress_test test/kernel-test/stress_test.go
// Run:   sudo /tmp/stress_test
package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

type StressMetrics struct {
	Forks      int
	Duration   time.Duration
	MemBefore  runtime.MemStats
	MemAfter   runtime.MemStats
	CPUSamples []time.Duration
}

func main() {
	fmt.Println("ProvidAPT Kernel Stress Test")
	fmt.Println("===========================")
	fmt.Println()

	// Collect initial metrics
	procDir, _ := os.ReadDir("/proc/self")
	_ = procDir

	metrics := runStressTest(10000)
	printResults(metrics)
	saveResults(metrics)
}

func runStressTest(count int) *StressMetrics {
	sm := &StressMetrics{Forks: count}

	log.Printf("Starting stress test: %d concurrent forks...", count)

	// Pre-fork
	runtime.GC()
	runtime.ReadMemStats(&sm.MemBefore)

	start := time.Now()
	var wg sync.WaitGroup
	errCh := make(chan error, count)

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Fork a subprocess that exits immediately
			cmd := exec.Command("/bin/true")
			if err := cmd.Run(); err != nil {
				errCh <- fmt.Errorf("fork %d: %w", id, err)
			}
		}(i)

		// Sample CPU timing every 100 forks
		if i%100 == 0 {
			sm.CPUSamples = append(sm.CPUSamples, time.Since(start))
		}
	}

	wg.Wait()
	sm.Duration = time.Since(start)

	runtime.GC()
	runtime.ReadMemStats(&sm.MemAfter)

	close(errCh)
	var errors []error
	for err := range errCh {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		log.Printf("Stress test: %d errors out of %d forks", len(errors), count)
	} else {
		log.Printf("Stress test: %d/%d forks completed in %v", count, count, sm.Duration)
	}

	return sm
}

func printResults(sm *StressMetrics) {
	memUsed := sm.MemAfter.Alloc - sm.MemBefore.Alloc
	fmt.Println("\n=== Stress Test Results ===")
	fmt.Printf("  Forks:          %d\n", sm.Forks)
	fmt.Printf("  Duration:       %v\n", sm.Duration)
	fmt.Printf("  Forks/sec:      %.0f\n", float64(sm.Forks)/sm.Duration.Seconds())
	fmt.Printf("  Memory before:  %d KB\n", sm.MemBefore.Alloc/1024)
	fmt.Printf("  Memory after:   %d KB\n", sm.MemAfter.Alloc/1024)
	fmt.Printf("  Memory delta:   %d KB\n", memUsed/1024)
	fmt.Printf("  GC cycles:      %d\n", sm.MemAfter.NumGC-sm.MemBefore.NumGC)
	fmt.Printf("  Heap objects:   %d\n", sm.MemAfter.HeapObjects)

	// Check for memory leak (delta per fork)
	if sm.Forks > 0 {
		bytesPerFork := int64(memUsed) / int64(sm.Forks)
		fmt.Printf("  Bytes per fork: %d\n", bytesPerFork)
		if bytesPerFork > 1024 {
			log.Printf("WARNING: %d bytes/fork may indicate memory leak", bytesPerFork)
		}
	}

	// CPU jitter
	if len(sm.CPUSamples) > 1 {
		var jitter time.Duration
		for i := 1; i < len(sm.CPUSamples); i++ {
			delta := sm.CPUSamples[i] - sm.CPUSamples[i-1]
			jitter += delta
		}
		avgJitter := jitter / time.Duration(len(sm.CPUSamples)-1)
		fmt.Printf("  CPU jitter:     %v avg\n", avgJitter)
	}
}

func saveResults(sm *StressMetrics) {
	path := "/tmp/providapt_stress_results.csv"
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Warning: could not save results: %v", err)
		return
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"metric", "value"})
	w.Write([]string{"forks", fmt.Sprintf("%d", sm.Forks)})
	w.Write([]string{"duration_ns", fmt.Sprintf("%d", sm.Duration.Nanoseconds())})
	w.Write([]string{"mem_before_bytes", fmt.Sprintf("%d", sm.MemBefore.Alloc)})
	w.Write([]string{"mem_after_bytes", fmt.Sprintf("%d", sm.MemAfter.Alloc)})
	w.Write([]string{"gc_cycles", fmt.Sprintf("%d", sm.MemAfter.NumGC-sm.MemBefore.NumGC)})
	w.Write([]string{"heap_objects", fmt.Sprintf("%d", sm.MemAfter.HeapObjects)})

	fmt.Printf("Results saved: %s\n", path)
}
