/**
 * Controller of the PAM_PASSWORD_POLICY field type: the password policies
 * to choose from. Empty means the default: the platform's, for a connection
 * ("pam-password-policy"), or else the built-in rules.
 */
angular.module('guacPam').controller('pamPasswordPolicyFieldController', ['$scope', '$injector',
        function pamPasswordPolicyFieldController($scope, $injector) {

    var pamService = $injector.get('pamService');

    // An empty value is no policy chosen, as the empty option shows it
    if ($scope.model === '')
        $scope.model = null;

    /**
     * The policies, as { id, name }, or null while loading.
     */
    $scope.policies = null;

    /**
     * Whether this is a connection's choice, whose default is its platform's.
     */
    $scope.ofConnection = $scope.field.name.indexOf('pam-') === 0;

    pamService.getPasswordPolicies().then(function policiesRetrieved(policies) {
        $scope.policies = policies.map(function toChoice(policy) {
            return { id : String(policy.id), name : policy.name };
        });
        // A policy no longer listed still shows as chosen, until changed
        if ($scope.model && !$scope.policies.some(function isChosen(policy) { return policy.id === $scope.model; }))
            $scope.policies.push({ id : $scope.model, name : '#' + $scope.model });
    }, function policiesFailed() {
        $scope.policies = [];
    });

}]);
