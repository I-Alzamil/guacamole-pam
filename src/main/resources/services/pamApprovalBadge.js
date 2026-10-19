/**
 * Number of requests awaiting the current user's decision, for the yellow
 * badges next to the user menu and on the Approvals tab.
 */
angular.module('guacPam').factory('pamApprovalBadge', ['$injector', function pamApprovalBadge($injector) {

    var pamBadgeCounter = $injector.get('pamBadgeCounter');
    var pamService      = $injector.get('pamService');

    return pamBadgeCounter(function countApprovals() {
        return pamService.countApprovals().then(function counted(result) {
            return result.pending;
        });
    });

}]);
