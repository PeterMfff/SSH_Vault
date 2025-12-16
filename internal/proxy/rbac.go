package proxy

// [ĐÃ SỬA] Xóa thư viện "strings" bị thừa đi
type Policy struct {
	Role           string
	AllowedTargets []string
}

type RBACService struct {
	policies map[string]Policy
}

func NewRBACService() *RBACService {
	return &RBACService{
		policies: make(map[string]Policy),
	}
}

func (r *RBACService) AddPolicy(user, role string, targets []string) {
	r.policies[user] = Policy{
		Role:           role,
		AllowedTargets: targets,
	}
}

// CheckAccess kiểm tra xem user có được phép vào targetIP hay không
func (r *RBACService) CheckAccess(user, targetIP string) (bool, string) {
	policy, exists := r.policies[user]
	if !exists {
		return false, "" 
	}

	for _, t := range policy.AllowedTargets {
		if t == "*" || t == targetIP {
			return true, policy.Role
		}
	}
	return false, ""
}

