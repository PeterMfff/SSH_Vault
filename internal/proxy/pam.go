package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"github.com/Entidi89/ssh_proxy1/internal/vault"
)

type PamSessionWrapper struct {
	Stdin   io.WriteCloser
	Stdout  io.Reader
	Client  *ssh.Client
	Session *ssh.Session
}

func (p *PamSessionWrapper) Read(b []byte) (int, error)  { return p.Stdout.Read(b) }
func (p *PamSessionWrapper) Write(b []byte) (int, error) { return p.Stdin.Write(b) }
func (p *PamSessionWrapper) Close() error {
	p.Session.Close()
	p.Client.Close()
	return nil
}

// ConnectUsingVault: Kết nối SSH sử dụng Certificate từ Vault
func ConnectUsingVault(v *vault.VaultClient, targetAddr, targetUser, roleName string) (io.ReadWriteCloser, error) {
	// 1. Sinh khóa RSA dùng 1 lần (Ephemeral Key)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("sinh key lỗi: %v", err)
	}
	
	// Chuyển đổi RSA Key sang SSH Signer
	signerFromKey, err := ssh.NewSignerFromKey(privateKey) 
	if err != nil {
		return nil, err
	}

	// Tạo Public Key để gửi đi
	pubKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil { return nil, err }
	
	// 2. Gửi sang Vault để xin chữ ký
	// Truyền roleName vào thay vì hardcode
	signedCert, err := v.SignSSHKey(ssh.MarshalAuthorizedKey(pubKey), roleName, targetUser)
	if err != nil {
		return nil, fmt.Errorf("Vault từ chối cấp Role '%s': %v", roleName, err)
	}

	// 3. Tạo Signer từ Certificate (Giấy phép đã ký)
	certKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signedCert))
	if err != nil { return nil, err }
	cert := certKey.(*ssh.Certificate)

	certSigner, err := ssh.NewCertSigner(cert, signerFromKey)
	if err != nil { return nil, err }

	// 4. Kết nối tới Server đích
	// Đảm bảo địa chỉ có port
	if !strings.Contains(targetAddr, ":") { targetAddr += ":22" }
	
	clientConfig := &ssh.ClientConfig{
		User: targetUser,
		Auth: []ssh.AuthMethod{ ssh.PublicKeys(certSigner) }, // Dùng Cert để login
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),         // Bỏ qua check host key
		Timeout: 5 * time.Second,
	}

	client, err := ssh.Dial("tcp", targetAddr, clientConfig)
	if err != nil { return nil, err }

	session, err := client.NewSession()
	if err != nil { client.Close(); return nil, err }

	// [ĐÃ SỬA] Request Terminal (PTY)
	// Bỏ các modes phức tạp đi, chỉ gửi map rỗng để tránh lỗi "pty-req failed"
	modes := ssh.TerminalModes{} 
	
	// Dùng "xterm" hoặc "xterm-256color"
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		session.Close()
		client.Close()
		// In lỗi rõ hơn để debug
		return nil, fmt.Errorf("lỗi xin cấp PTY (RequestPty): %v", err)
	}

	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	
	// Bắt đầu Shell
	if err := session.Shell(); err != nil {
		session.Close(); client.Close(); return nil, err
	}

	return &PamSessionWrapper{Stdin: stdin, Stdout: stdout, Client: client, Session: session}, nil
}
