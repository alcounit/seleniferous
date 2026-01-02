package pathutils

import (
	"path"
	"strings"
)

func Delete(path string, delete ...string) string {
	fragments := Parse(path)
	if len(fragments) < 1 {
		return path
	}

	ntr := make(map[string]struct{}, len(delete))
	for _, name := range delete {
		ntr[name] = struct{}{}
	}

	var result []string
	for _, pathname := range fragments {
		if _, found := ntr[pathname]; !found {
			result = append(result, pathname)
		}
	}

	newPath := Build(result)

	if strings.HasSuffix(path, "/") {
		newPath = newPath + "/"
	}

	return newPath
}

func Replace(path string, replace map[string]string) string {
	newPath := path
	for old, newVal := range replace {
		newPath = strings.ReplaceAll(newPath, old, newVal)
	}
	return Build(Parse(newPath))
}

func Parse(path string) []string {
	pathnames := strings.Split(strings.TrimPrefix(strings.TrimSuffix(path, "/"), "/"), "/")
	return pathnames
}

func Build(pathnames []string) string {
	return path.Join("/", strings.Join(pathnames, "/"))
}
