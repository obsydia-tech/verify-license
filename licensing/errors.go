package licensing

import "fmt"

func errTier(have, want string) error {
	return fmt.Errorf("licence tier %s does not match requested tier %s", have, want)
}

func errNodes(have, want int) error {
	return fmt.Errorf("licence allows %d nodes, requested %d", have, want)
}
