package vault

import (
	"fmt"
	"log"
	"strings"
	
	vault "github.com/hashicorp/vault/api"
)

func (v *VaultClient) ConfigurePAMSystem() error {
	log.Println("[CORE PAM] Đang kiểm tra hệ thống Vault...")

	// 1. Kiểm tra và Bật SSH Engine
	mounts, err := v.client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("không thể liệt kê mounts: %v", err)
	}
	
	if _, ok := mounts["ssh-client-signer/"]; !ok {
		log.Println("[CORE PAM] SSH Engine chưa bật -> Đang kích hoạt...")
		mountInput := &vault.MountInput{Type: "ssh"}
		if err := v.client.Sys().Mount("ssh-client-signer", mountInput); err != nil {
			return fmt.Errorf("lỗi bật ssh engine: %v", err)
		}
	}

	// 2. Kiểm tra/Tạo CA Key
	log.Println("[CORE PAM] Đang cấu hình CA Signing Key...")
	caConfigPath := "ssh-client-signer/config/ca"
	caData := map[string]interface{}{"generate_signing_key": true}

	_, err = v.client.Logical().Write(caConfigPath, caData)
	if err != nil {
		if strings.Contains(err.Error(), "keys are already configured") {
			log.Println("[CORE PAM] CA Key đã tồn tại -> Tiếp tục sử dụng Key cũ.")
		} else {
			return fmt.Errorf("lỗi cấu hình CA: %v", err)
		}
	} else {
		log.Println("[CORE PAM] Đã sinh CA Key mới thành công.")
	}

	// 3. Cập nhật Role Admin
	log.Println("[CORE PAM] Cập nhật Role: admin-role (Full Permission)...")
	adminRolePath := "ssh-client-signer/roles/admin-role"
	
	// [ĐÃ SỬA] default_extensions phải là Map, không phải String
	defaultExts := map[string]string{
		"permit-pty":              "",
		"permit-port-forwarding":  "",
		"permit-agent-forwarding": "",
		"permit-user-rc":          "",
		"permit-X11-forwarding":   "",
	}

	adminRoleData := map[string]interface{}{
		"allow_user_certificates": true,
		"allowed_users":           "*",
		"default_user":            "root",
		"ttl":                     "1h0m0s",
		"key_type":                "ca",
		"allowed_extensions":      "permit-pty,permit-port-forwarding,permit-agent-forwarding,permit-user-rc,permit-X11-forwarding",
		"default_extensions":      defaultExts, // Truyền Map vào đây
	}
	if _, err := v.client.Logical().Write(adminRolePath, adminRoleData); err != nil {
		return fmt.Errorf("lỗi tạo admin-role: %v", err)
	}

	// Cập nhật Role Dev
	log.Println("[CORE PAM] Cập nhật Role: dev-role...")
	devRolePath := "ssh-client-signer/roles/dev-role"
	devExts := map[string]string{
		"permit-pty":             "",
		"permit-port-forwarding": "",
	}
	devRoleData := map[string]interface{}{
		"allow_user_certificates": true,
		"allowed_users":           "ubuntu,ec2-user,testuser,wazuhserver", 
		"default_user":            "ubuntu",
		"ttl":                     "15m0s",
		"key_type":                "ca",
		"allowed_extensions":      "permit-pty,permit-port-forwarding",
		"default_extensions":      devExts, // Truyền Map vào đây
	}
	if _, err := v.client.Logical().Write(devRolePath, devRoleData); err != nil {
		return fmt.Errorf("lỗi tạo dev-role: %v", err)
	}

	log.Println("[CORE PAM] >>> Hệ thống phân quyền đã sẵn sàng! <<<")
	return nil
}

func (v *VaultClient) GetCAPublicKey() (string, error) {
	secret, err := v.client.Logical().Read("ssh-client-signer/config/ca")
	if err != nil || secret == nil {
		return "", err
	}
	return secret.Data["public_key"].(string), nil
}
