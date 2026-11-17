package waf

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func referenceDirectory(t *testing.T, language string, stage int) string {
	t.Helper()
	base := filepath.Join("testdata", "references")
	if stage <= 3 {
		base = filepath.Join(courseRoot(), "solutions")
	}
	directory, err := filepath.Abs(filepath.Join(base, language, fmt.Sprintf("%02d-%s", stage, slugs[stage-1]), "code"))
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func referenceLaunch(t *testing.T, directory string) launchFunc {
	t.Helper()
	return func(origin, detector, policy string) (func(), error) {
		if err := portAvailable(); err != nil {
			return nil, err
		}
		temp := t.TempDir()
		path := filepath.Join(temp, "policy.json")
		os.WriteFile(path, []byte(policy), 0600)
		command := exec.Command(filepath.Join(directory, "your_program.sh"), "--origin", origin, "--detector", detector, "--policy", path)
		command.Dir = temp
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		log, err := os.Create(filepath.Join(temp, "learner.log"))
		if err != nil {
			return nil, err
		}
		command.Stdout = log
		command.Stderr = log
		if err := command.Start(); err != nil {
			log.Close()
			return nil, err
		}
		done := make(chan struct{})
		go func() { command.Wait(); close(done) }()
		var once sync.Once
		stop := func() {
			once.Do(func() {
				syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
				select {
				case <-done:
				case <-time.After(time.Second):
					syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
					<-done
				}
				log.Close()
			})
		}
		t.Cleanup(stop)
		if err := waitHealth(done); err != nil {
			stop()
			body, _ := os.ReadFile(log.Name())
			return nil, fmt.Errorf("%w: %s", err, body)
		}
		return stop, nil
	}
}

// Each cumulative reference implements the behavior introduced by its own stage.
func TestStageReferences(t *testing.T) {
	// Arrange
	for _, language := range []string{"go", "python"} {
		for i := range slugs {
			t.Run(fmt.Sprintf("%s/stage-%02d", language, i+1), func(t *testing.T) {
				directory := referenceDirectory(t, language, i+1)
				// Act
				err := verify(i+1, referenceLaunch(t, directory), t.Logf)
				// Assert
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// A previous-stage reference cannot pass a stage that introduces a new control.
func TestPreviousStageFails(t *testing.T) {
	// Arrange
	for _, language := range []string{"go", "python"} {
		for i := 1; i < len(slugs); i++ {
			t.Run(fmt.Sprintf("%s/stage-%02d", language, i+1), func(t *testing.T) {
				directory := referenceDirectory(t, language, i)
				// Act
				err := verify(i+1, referenceLaunch(t, directory), t.Logf)
				// Assert
				if err == nil {
					t.Fatal("previous-stage implementation incorrectly passed")
				}
			})
		}
	}
}

// The active course's stage IDs and order match the grader registrations.
func TestCourseStageRegistration(t *testing.T) {
	// Arrange
	data, err := os.ReadFile("course-definition.yml")
	if err != nil {
		t.Fatal(err)
	}
	var course struct {
		Stages []struct {
			Slug string `yaml:"slug"`
		} `yaml:"stages"`
	}
	// Act
	err = yaml.Unmarshal(data, &course)
	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if len(course.Stages) != len(slugs) {
		t.Fatalf("expected %d stages, got %d", len(slugs), len(course.Stages))
	}
	for index, stage := range course.Stages {
		if stage.Slug != slugs[index] {
			t.Fatalf("stage %d: expected %s, got %s", index+1, slugs[index], stage.Slug)
		}
	}
}
