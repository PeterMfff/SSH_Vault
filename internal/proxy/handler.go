package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"github.com/Entidi89/ssh_proxy1/internal/vault"
)

// getOrCreateHostKey: Hàm này giúp Proxy "nhớ" chìa khóa của mình
func getOrCreateHostKey() (ssh.Signer, error) {
	keyFile := "proxy_id_rsa" // Tên file lưu chìa khóa

	// 1. Thử đọc file chìa khóa cũ
	content, err := os.ReadFile(keyFile)
	if err == nil {
		// Nếu có file -> Đọc và dùng lại
		signer, err := ssh.ParsePrivateKey(content)
		if err != nil {
			return nil, err
		}
		return signer, nil
	}

	// 2. Nếu chưa có file -> Tạo mới
	log.Println("[PROXY] Đang tạo Host Key mới và lưu vào file...")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Lưu xuống file để lần sau dùng lại
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	file, err := os.Create(keyFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := pem.Encode(file, pemBlock); err != nil {
		return nil, err
	}

	// Trả về signer
	return ssh.NewSignerFromKey(key)
}

func HandleConnection(nConn net.Conn, vClient *vault.VaultClient, rbac *RBACService) {
	defer nConn.Close()

	// Cấu hình SSH Server
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}

	// [FIX] Dùng hàm lấy Key cố định thay vì tạo ngẫu nhiên
	signer, err := getOrCreateHostKey()
	if err != nil {
		log.Printf("Lỗi tải Host Key: %v", err)
		return
	}
	config.AddHostKey(signer)

	// Bắt tay SSH
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("Lỗi handshake: %v", err)
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	// Xử lý logic kết nối
	inputString := sshConn.User()
	parts := strings.Split(inputString, "+")
	
	if len(parts) != 2 {
		log.Printf("[PROXY] Lỗi cú pháp từ %s. Yêu cầu: user+ip", nConn.RemoteAddr())
		return
	}
	
	proxyUser := parts[0]
	targetIP := parts[1]

	log.Printf("[PROXY] User '%s' yêu cầu vào '%s'", proxyUser, targetIP)

	// Kiểm tra RBAC
	allowed, roleName := rbac.CheckAccess(proxyUser, targetIP)
	if !allowed {
		log.Printf("[BLOCK] User '%s' bị chặn truy cập '%s'", proxyUser, targetIP)
		return
	}

	// Xác định User đích
	var targetOSUser string
	if roleName == "admin-role" {
		targetOSUser = "root"
	} else {
		targetOSUser = "wazuhserver" 
	}

	// Kết nối Vault & Target
	stream, err := ConnectUsingVault(vClient, targetIP, targetOSUser, roleName)
	if err != nil {
		log.Printf("[ERROR] Lỗi kết nối máy đích: %v", err)
		return
	}
	defer stream.Close()

	// Mở kênh dữ liệu
	newChannels := <-chans
	if newChannels == nil { return }

	if newChannels.ChannelType() != "session" {
		newChannels.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}
	channel, requests, err := newChannels.Accept()
	if err != nil { return }

	go func() {
		io.Copy(channel, stream)
		channel.Close()
	}()
	go func() {
		io.Copy(stream, channel)
	}()
	
	req := <-requests
	if req != nil { req.Reply(true, nil) } 
	
	select {}
}
