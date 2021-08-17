package blockendpointeditrole

violation[{"msg": msg}] {
    input.review.object.metadata.name == "system:aggregate-to-edit"
    endpointRule(input.review.object.rules[_])
    msg := "ClusterRole system:aggregate-to-edit should not allowed endpoint permissions"
}

violation[{"msg": msg}] {
    input.review.object.metadata.name == "system:aggregate-to-edit"
    not disableAutoupdate(input.review.object.metadata.annotations)
    msg := "ClusterRole system:aggregate-to-edit is required rbac.authorization.kubernetes.io/autoupdate=false after reconciled none endpoint permission"
}

endpointRule(rule) {
    "endpoints" == rule.resources[_]
    hasEditVerb(rule.verbs)
}

hasEditVerb(verbs) {
	"create" == verbs[_]
}
hasEditVerb(verbs) {
    "patch" == verbs[_]
}
hasEditVerb(verbs) {
	"update" == verbs[_]
}

disableAutoupdate(annotations) {
	annotations["rbac.authorization.kubernetes.io/autoupdate"] == "false"
}
