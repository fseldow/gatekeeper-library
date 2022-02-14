package k8spspallowprivilegeescalationcontainer

import data.lib.exempt_container.is_exempt

# The following scenerios will be viewed as violations. Windows containers are not supported
## allowPrivilegeEscalation=true
## runAsUser != 0 + missing allowPrivilegeEscalation=false

violation[{"msg": msg, "details": {}}] {
    c := input_containers[_]
    not is_exempt(c)
    input_allow_privilege_escalation(c)
    msg := sprintf("Privilege escalation container is not allowed: %v", [c.name])
}

input_allow_privilege_escalation(c) {
    c.securityContext.allowPrivilegeEscalation == true
}
input_allow_privilege_escalation(c) {
    not c.securityContext.allowPrivilegeEscalation == false
    c.securityContext.runAsUser != 0
}
input_allow_privilege_escalation(c) {
    not c.securityContext.allowPrivilegeEscalation == false
    not c.securityContext.runAsUser
    input.review.object.spec.securityContext.runAsUser != 0
}
input_containers[c] {
    c := input.review.object.spec.containers[_]
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
