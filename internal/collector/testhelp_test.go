package collector

import "os"

func osChmod(p string, m uint32) error { return os.Chmod(p, os.FileMode(m)) }
