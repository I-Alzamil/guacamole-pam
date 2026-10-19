/**
 * Number of password and access requests awaiting the current user's
 * approval, kept current while they are logged in, for the badges next to
 * the user menu and on the Approvals tab.
 */
angular.module('guacPam').factory('pamApprovalBadge', ['$injector', function pamApprovalBadge($injector) {

    var $interval  = $injector.get('$interval');
    var pamService = $injector.get('pamService');

    /**
     * How often the count refreshes, in milliseconds.
     */
    var REFRESH_INTERVAL = 30000;

    var service = {};

    var pending = 0;

    var timer = null;

    service.count = function count() {
        return pending;
    };

    service.refresh = function refresh() {
        if (!timer)
            return;
        return pamService.countApprovals().then(function counted(result) {
            pending = timer ? result.pending || 0 : 0;
        }, function countFailed() {
            pending = 0;
        });
    };

    /**
     * Starts counting for an approver, or stops for anyone else.
     */
    service.start = function start(approver) {
        service.stop();
        if (!approver)
            return;
        timer = $interval(service.refresh, REFRESH_INTERVAL);
        service.refresh();
    };

    service.stop = function stop() {
        $interval.cancel(timer);
        timer = null;
        pending = 0;
    };

    return service;

}]);
