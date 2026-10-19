package compose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/truesignal/hub/internal/models"
)

func TestBuildService_SecurityDefaults(t *testing.T) {
	manifest := models.SensorManifest{
		Deployment: models.Deployment{
			ImageRepository: "test-image",
		},
	}
	compose, err := BuildService("test-sensor", manifest, map[string]string{})
	require.NoError(t, err)
	require.Len(t, compose.Services, 1)

	svc := compose.Services[0].Service
	assert.Equal(t, "65532:65532", svc.User, "should default to non-root user")
	assert.Equal(t, []string{"ALL"}, svc.CapDrop, "should drop all capabilities by default")
	assert.True(t, svc.ReadOnly, "should be readonly by default")
	assert.Contains(t, svc.SecurityOpt, "no-new-privileges:true", "should prevent new privileges")
}

func TestBuildService_CapabilityFiltering(t *testing.T) {
	manifest := models.SensorManifest{
		Deployment: models.Deployment{
			ImageRepository: "test-image",
			CapAdd:          []string{"NET_RAW", "SYS_ADMIN"}, // SYS_ADMIN is not allowed
		},
	}
	compose, err := BuildService("test-sensor", manifest, map[string]string{})
	require.NoError(t, err)
	require.Len(t, compose.Services, 1)

	svc := compose.Services[0].Service
	assert.Equal(t, []string{"NET_RAW"}, svc.CapAdd, "should filter out disallowed capabilities")
}

func TestBuildService_DynamicVolumeExpansion(t *testing.T) {
	t.Run("Dynamic File Bind", func(t *testing.T) {
		manifest := models.SensorManifest{
			Deployment: models.Deployment{
				ImageRepository: "test-image",
				VolumeMounts: []models.VolumeMount{
					{Type: models.DynamicFileBind, SourceEnv: "TS_FILES", TargetPrefix: "/watch/"},
				},
			},
		}
		envMap := map[string]string{"TS_FILES": "/opt/z.txt, /opt/a.txt, , /opt/m.txt"}

		compose, err := BuildService("test-sensor", manifest, envMap)
		require.NoError(t, err)
		svc := compose.Services[0].Service

		require.Len(t, svc.Volumes, 3)
		assert.Equal(t, "/watch//opt/a.txt", svc.Volumes[0].Target)
		assert.Equal(t, "/opt/a.txt", svc.Volumes[0].Source)
		assert.Equal(t, "/watch//opt/m.txt", svc.Volumes[1].Target)
		assert.Equal(t, "/watch//opt/z.txt", svc.Volumes[2].Target)
	})

	t.Run("Dynamic Dir Bind", func(t *testing.T) {
		manifest := models.SensorManifest{
			Deployment: models.Deployment{
				InitContainers: []models.InitContainer{
					{Name: "init", VolumeMounts: []models.VolumeMount{
						{Type: models.DynamicDirBind, SourceEnv: "TS_FILES", TargetPrefix: "/watch/"},
					}},
				},
			},
		}
		envMap := map[string]string{"TS_FILES": "/opt/z/file.txt, /opt/a/file.txt, /opt/a/another.txt"}

		compose, err := BuildService("test-sensor", manifest, envMap)
		require.NoError(t, err)
		initSvc := compose.Services[0].Service

		require.Len(t, initSvc.Volumes, 2)
		assert.Equal(t, "/watch//opt/a", initSvc.Volumes[0].Target)
		assert.Equal(t, "/opt/a", initSvc.Volumes[0].Source)
		assert.Equal(t, "/watch//opt/z", initSvc.Volumes[1].Target)
	})

	t.Run("Dynamic Mount Security Block", func(t *testing.T) {
		manifest := models.SensorManifest{
			Deployment: models.Deployment{
				VolumeMounts: []models.VolumeMount{
					{Type: models.DynamicFileBind, SourceEnv: "TS_FILES", TargetPrefix: "/watch/"},
				},
			},
		}
		_, err := BuildService("test-sensor", manifest, map[string]string{"TS_FILES": "/etc/passwd"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mount path is forbidden: /etc/passwd")
	})
}

func TestBuildService_InitContainers(t *testing.T) {
	manifest := models.SensorManifest{
		Deployment: models.Deployment{
			ImageRepository: "main-image",
			InitContainers: []models.InitContainer{
				{Name: "z-init", ImageRepository: "init-z"},
				{Name: "a-init", ImageRepository: "init-a"},
			},
		},
	}
	envMap := map[string]string{
		"TS_SENSOR_ID": "sensor123",
		"TS_HUB_KEY":   "key123",
		"CUSTOM_VAR":   "value123",
	}

	compose, err := BuildService("test-sensor", manifest, envMap)
	require.NoError(t, err)
	require.Len(t, compose.Services, 3) // 2 init + 1 main

	assert.Equal(t, "a-init", compose.Services[0].Name, "init containers should be sorted by name")
	assert.Equal(t, "z-init", compose.Services[1].Name)

	initSvc := compose.Services[0].Service
	assert.Equal(t, []string{"CUSTOM_VAR=value123"}, initSvc.Environment, "init containers should not get core env vars")

	mainSvc := compose.Services[2].Service
	require.Len(t, mainSvc.DependsOn, 2)
	assert.Equal(t, "service_completed_successfully", mainSvc.DependsOn["a-init"].Condition)
}

func TestSortEnvKeys(t *testing.T) {
	keys := []string{"FOO", "TS_HUB_KEY", "BAR", "TS_SENSOR_ID", "TS_SEVERITY"}
	sortEnvKeys(keys)
	expected := []string{"TS_SENSOR_ID", "TS_HUB_KEY", "TS_SEVERITY", "BAR", "FOO"}
	assert.Equal(t, expected, keys)
}
func TestBuildService_InitContainerBaselineAndEnvEscaping(t *testing.T) {
	m := models.SensorManifest{
		Deployment: models.Deployment{
			ImageRepository: "img",
			ImageTag:        "v1",
			InitContainers: []models.InitContainer{{
				Name:            "prov",
				ImageRepository: "img",
				ImageTag:        "v1",
				User:            "0:0",
				CapAdd:          []string{"DAC_OVERRIDE", "NET_ADMIN"},
				VolumeMounts: []models.VolumeMount{{
					Type: models.DynamicDirBind, SourceEnv: "TS_DECOY_FILES", TargetPrefix: "/host",
				}},
			}},
		},
	}
	env := map[string]string{"TS_DECOY_FILES": "/opt/app/.env.backup", "TS_TARPIT_BANNER": "price=$5"}
	cf, err := BuildService("ts-sensor-x", m, env)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	init := cf.Services[0].Service
	if init.NetworkMode != "none" || !init.ReadOnly || len(init.CapDrop) != 1 || init.CapDrop[0] != "ALL" {
		t.Errorf("init container must be network-less, read-only, cap_drop ALL: %+v", init)
	}
	if len(init.SecurityOpt) != 1 || init.SecurityOpt[0] != "no-new-privileges:true" {
		t.Errorf("init container must set no-new-privileges: %v", init.SecurityOpt)
	}
	if len(init.CapAdd) != 1 || init.CapAdd[0] != "DAC_OVERRIDE" {
		t.Errorf("NET_ADMIN must be filtered, got %v", init.CapAdd)
	}
	if len(init.Volumes) != 1 || init.Volumes[0].Source != "/opt/app" || init.Volumes[0].Target != "/host/opt/app" {
		t.Errorf("unexpected dynamic dir bind: %+v", init.Volumes)
	}

	main := cf.Services[1].Service
	found := false
	for _, e := range main.Environment {
		if e == "TS_TARPIT_BANNER=price=$$5" {
			found = true
		}
	}
	if !found {
		t.Errorf("'$' must be escaped for compose interpolation: %v", main.Environment)
	}
}

func TestBuildService_RejectsForbiddenDynamicMounts(t *testing.T) {
	m := models.SensorManifest{Deployment: models.Deployment{
		ImageRepository: "img",
		VolumeMounts:    []models.VolumeMount{{Type: models.DynamicFileBind, SourceEnv: "TS_DECOY_FILES", TargetPrefix: "/canaries"}},
		InitContainers: []models.InitContainer{{Name: "p", ImageRepository: "img",
			VolumeMounts: []models.VolumeMount{{Type: models.DynamicDirBind, SourceEnv: "TS_DECOY_FILES", TargetPrefix: "/host"}}}},
	}}
	for _, bad := range []string{"/run/docker.sock", "/x", "relative/file", "/var/lib/docker/x"} {
		if _, err := BuildService("ts-sensor-x", m, map[string]string{"TS_DECOY_FILES": bad}); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}
