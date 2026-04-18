package platform

import "testing"

func TestDetectFromOSReleaseSecurityDistros(t *testing.T) {
	tests := []struct {
		name     string
		fields   map[string]string
		markers  map[string]bool
		want     Distro
		security bool
		pkg      string
		display  string
	}{
		{
			name:     "kali",
			fields:   map[string]string{"ID": "kali", "VERSION": "2026.1", "PRETTY_NAME": "Kali GNU/Linux Rolling"},
			want:     DistroKali,
			security: true,
			pkg:      "apt",
			display:  "Kali Linux",
		},
		{
			name:     "parrot",
			fields:   map[string]string{"ID": "parrot", "VERSION_ID": "6.0", "PRETTY_NAME": "Parrot OS"},
			want:     DistroParrot,
			security: true,
			pkg:      "apt",
			display:  "Parrot OS",
		},
		{
			name:     "blackarch marker",
			fields:   map[string]string{"ID": "arch", "ID_LIKE": "arch", "PRETTY_NAME": "Arch Linux"},
			markers:  map[string]bool{"/etc/pacman.d/blackarch-mirrorlist": true},
			want:     DistroBlackArch,
			security: true,
			pkg:      "pacman",
			display:  "BlackArch Linux",
		},
		{
			name:     "debian",
			fields:   map[string]string{"ID": "debian", "VERSION_ID": "12", "PRETTY_NAME": "Debian GNU/Linux 12"},
			want:     DistroLinux,
			security: false,
			display:  "Debian GNU/Linux 12",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := DetectFromOSRelease(tt.fields, func(path string) bool {
				return tt.markers[path]
			})

			if env.Distro != tt.want {
				t.Fatalf("Distro = %q, want %q", env.Distro, tt.want)
			}
			if env.IsSecurityOS != tt.security {
				t.Fatalf("IsSecurityOS = %v, want %v", env.IsSecurityOS, tt.security)
			}
			if tt.pkg != "" && env.PackageManager() != tt.pkg {
				t.Fatalf("PackageManager = %q, want %q", env.PackageManager(), tt.pkg)
			}
			if env.DisplayName() != tt.display {
				t.Fatalf("DisplayName = %q, want %q", env.DisplayName(), tt.display)
			}
		})
	}
}
