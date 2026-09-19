package cli

import stigprofile "github.com/Exonical/stigctl/internal/profile"

func validateProfile(id string) error {
	_, err := stigprofile.NewStore(contentRoot).Resolve(id)
	return err
}
