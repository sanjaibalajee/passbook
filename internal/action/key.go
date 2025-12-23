package action

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"passbook/internal/backend/crypto/age"
)

// KeyShow shows the user's public key
func (a *Action) KeyShow(c *cli.Context) error {
	if a.cfg.Identity.PublicKey != "" {
		fmt.Printf("Public Key: %s\n", a.cfg.Identity.PublicKey)
	} else {
		// Try to read from identity file
		pubKey, err := age.GetPublicKeyFromFile(a.cfg.IdentityPath())
		if err != nil {
			return fmt.Errorf("no identity found: %w", err)
		}
		fmt.Printf("Public Key: %s\n", pubKey)
	}

	// Check if encrypted
	encrypted, err := age.IsKeyEncrypted(a.cfg.IdentityPath())
	if err == nil {
		if encrypted {
			fmt.Println("Status:     Passphrase-protected")
		} else {
			fmt.Println("Status:     Unencrypted (consider running 'passbook key encrypt')")
		}
	}

	fmt.Printf("Key File:   %s\n", a.cfg.IdentityPath())
	return nil
}

// KeyEncrypt encrypts the private key with a passphrase
func (a *Action) KeyEncrypt(c *cli.Context) error {
	identityPath := a.cfg.IdentityPath()

	// Check if already encrypted
	encrypted, err := age.IsKeyEncrypted(identityPath)
	if err != nil {
		return fmt.Errorf("failed to check key status: %w", err)
	}

	if encrypted {
		return fmt.Errorf("key is already passphrase-protected. Use 'passbook key change-passphrase' to change it")
	}

	// Prompt for new passphrase
	passphrase, err := age.PromptPassphraseConfirm("Enter new passphrase: ")
	if err != nil {
		return err
	}

	if passphrase == "" {
		return fmt.Errorf("passphrase cannot be empty")
	}

	// Encrypt the key
	if err := age.EncryptExistingKey(identityPath, passphrase); err != nil {
		return fmt.Errorf("failed to encrypt key: %w", err)
	}

	fmt.Println("✓ Private key is now passphrase-protected")
	fmt.Println("\nIMPORTANT: Remember your passphrase! If you forget it, you will lose")
	fmt.Println("access to all encrypted secrets. There is no recovery mechanism.")

	return nil
}

// KeyDecrypt removes passphrase protection from the private key
func (a *Action) KeyDecrypt(c *cli.Context) error {
	identityPath := a.cfg.IdentityPath()

	// Check if encrypted
	encrypted, err := age.IsKeyEncrypted(identityPath)
	if err != nil {
		return fmt.Errorf("failed to check key status: %w", err)
	}

	if !encrypted {
		return fmt.Errorf("key is not passphrase-protected")
	}

	// Prompt for current passphrase
	passphrase, err := age.PromptPassphrase("Enter current passphrase: ")
	if err != nil {
		return err
	}

	// Decrypt the key
	if err := age.DecryptKeyFile(identityPath, passphrase); err != nil {
		return fmt.Errorf("failed to decrypt key: %w", err)
	}

	fmt.Println("✓ Passphrase protection removed")
	fmt.Println("\nWARNING: Your private key is now stored in plaintext.")
	fmt.Println("Anyone with access to your filesystem can read it.")

	return nil
}

// KeyChangePassphrase changes the passphrase on an encrypted key
func (a *Action) KeyChangePassphrase(c *cli.Context) error {
	identityPath := a.cfg.IdentityPath()

	// Check if encrypted
	encrypted, err := age.IsKeyEncrypted(identityPath)
	if err != nil {
		return fmt.Errorf("failed to check key status: %w", err)
	}

	if !encrypted {
		return fmt.Errorf("key is not passphrase-protected. Use 'passbook key encrypt' first")
	}

	// Prompt for current passphrase
	oldPassphrase, err := age.PromptPassphrase("Enter current passphrase: ")
	if err != nil {
		return err
	}

	// Prompt for new passphrase
	newPassphrase, err := age.PromptPassphraseConfirm("Enter new passphrase: ")
	if err != nil {
		return err
	}

	if newPassphrase == "" {
		return fmt.Errorf("new passphrase cannot be empty")
	}

	// Change the passphrase
	if err := age.ChangePassphrase(identityPath, oldPassphrase, newPassphrase); err != nil {
		return fmt.Errorf("failed to change passphrase: %w", err)
	}

	fmt.Println("✓ Passphrase changed successfully")

	return nil
}
