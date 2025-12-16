package main

import (
	"encoding/json"
	"log"
	"net"
	"os"

	"github.com/Entidi89/ssh_proxy1/internal/proxy"
	"github.com/Entidi89/ssh_proxy1/internal/vault"
)

// Cấu trúc để hứng dữ liệu từ file JSON
type PolicyConfig struct {
	User    string   `json:"user"`
	Role    string   `json:"role"`
	Targets []string `json:"targets"`
}

func main() {
	// 1. Khởi động Vault Client
	log.Println("[INIT] Đang khởi động Core PAM Engine...")
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")
	
	if vaultAddr == "" || vaultToken == "" {
		log.Fatal("Thiếu biến môi trường VAULT_ADDR hoặc VAULT_TOKEN")
	}

	vaultClient, err := vault.NewVaultClient(vaultAddr, vaultToken)
	if err != nil {
		log.Fatalf("Lỗi kết nối Vault: %v", err)
	}

	// 2. Cấu hình hệ thống (Tạo Key, Role...)
	if err := vaultClient.ConfigurePAMSystem(); err != nil {
		log.Fatalf("Lỗi khởi tạo hệ thống PAM: %v", err)
	}

	// 3. Cấu hình RBAC TỪ FILE JSON (NÂNG CẤP)
	rbacService := proxy.NewRBACService()
	
	// Đọc file policies.json
	log.Println("[INIT] Đang đọc cấu hình từ policies.json...")
	configFile, err := os.ReadFile("policies.json")
	if err != nil {
		log.Fatalf("Không thể đọc file policies.json: %v", err)
	}

	var policies []PolicyConfig
	if err := json.Unmarshal(configFile, &policies); err != nil {
		log.Fatalf("Lỗi cú pháp trong file JSON: %v", err)
	}

	// Nạp từng người vào hệ thống
	for _, p := range policies {
		//log.Printf(">>> Đã thêm quyền: User=%s | Role=%s | Targets=%v", p.User, p.Role, p.Targets)
		rbacService.AddPolicy(p.User, p.Role, p.Targets)
	}
        log.Println("[INIT] Đã nạp xong danh sách phân quyền (RBAC).")

	// 4. Khởi động Server Proxy
	listener, err := net.Listen("tcp", "0.0.0.0:3023")
	if err != nil {
		log.Fatalf("Không thể mở port 3023: %v", err)
	}
	defer listener.Close()

	log.Println("[PROXY] Server đang chạy tại 0.0.0.0:3023...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Lỗi chấp nhận kết nối: %v", err)
			continue
		}
		go proxy.HandleConnection(conn, vaultClient, rbacService)
	}
}
