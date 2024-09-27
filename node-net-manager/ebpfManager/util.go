package ebpfManager

import (
	"os"
)

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		// Might be other errors like permission denied
		return false
	}
	return !info.IsDir() // Ensure the path is not a directory
}
