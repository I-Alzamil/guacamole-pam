/**
 * Number of managed connections whose last rotation failed or could not be
 * confirmed, for the red badges of administrators next to the user menu and
 * on the Password Rotation tab.
 */
angular.module('guacPam').factory('pamRotationBadge', ['$injector', function pamRotationBadge($injector) {

    var pamBadgeCounter = $injector.get('pamBadgeCounter');
    var pamService      = $injector.get('pamService');

    return pamBadgeCounter(function countFailures() {
        return pamService.countRotationFailures().then(function counted(result) {
            return result.failed;
        });
    });

}]);
