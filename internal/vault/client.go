package vault

import (
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type VaultClient struct {
	client *vault.Client
}

// [SỬA] Thêm tham số addr và token vào hàm khởi tạo
func NewVaultClient(addr, token string) (*VaultClient, error) {
	config := vault.DefaultConfig()
	config.Address = addr
	config.Timeout = 10 * time.Second

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}

	client.SetToken(token)
	
	// Kiểm tra kết nối thử
	if _, err := client.Auth().Token().LookupSelf(); err != nil {
		return nil, fmt.Errorf("token không hợp lệ hoặc không kết nối được Vault: %v", err)
	}

	return &VaultClient{client: client}, nil
}

// Hàm ký Key (Giữ nguyên)
func (v *VaultClient) SignSSHKey(pubKey []byte, role, validPrincipal string) (string, error) {
	path := fmt.Sprintf("ssh-client-signer/sign/%s", role)
	
	data := map[string]interface{}{
		"public_key":      string(pubKey),
		"valid_principals": validPrincipal,
	}

	secret, err := v.client.Logical().Write(path, data)
	if err != nil {
		return "", err
	}

	signedKey, ok := secret.Data["signed_key"].(string)
	if !ok {
		return "", fmt.Errorf("không tìm thấy signed_key trong phản hồi")
	}

	return signedKey, nil
}
